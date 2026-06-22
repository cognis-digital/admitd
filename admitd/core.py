"""Core policy engine for admitd.

admitd is a clean-room, policy-as-code admission engine for Kubernetes. It
consumes a Kubernetes object (a Pod, Deployment, DaemonSet, … or an
AdmissionReview that wraps one) and evaluates it against a set of declarative
policies. Each policy yields a *decision* — ``allow``, ``deny``, or ``mutate``
(a JSONPatch) — together with a human-readable reason.

Design contract:
  * Standard library only — json, re, hashlib. No third-party dependencies.
  * Deterministic and side-effect free. The optional AI layer
    (``admitd._ai_backend``) is off by default and never runs unless the caller
    explicitly opts in via the CLI.
  * No network access in this module; everything is computed locally.

The policy language is intentionally small but expressive. A policy is a plain
object (parsed from JSON or the bundled YAML-subset reader) with these fields::

    {
      "id": "ADMITD-PRIV-001",
      "title": "Deny privileged containers",
      "severity": "critical",
      "control": "NSA-CISA Kubernetes Hardening / CIS 5.2.x",
      "match": {"kinds": ["Pod", "Deployment", ...]},   # optional; default all
      "rules": [ {<rule>}, ... ],
      "action": "deny"                                   # deny | mutate | warn
    }

A *rule* describes a check over the object's container specs (or the object
itself). See ``_RULE_KINDS`` for the supported rule verbs. Built-in policies
mapped to public CIS / NSA-CISA Kubernetes hardening concepts live in
``builtin_policies()`` — these are original re-expressions of widely published
hardening guidance, not copied from any third-party engine.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# Tool identity (re-exported from the package __init__).
TOOL_NAME = "admitd"
TOOL_VERSION = "0.1.0"

# Severity ordering, highest first. Used for sorting + exit-code policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Container-bearing workload kinds and where their pod template lives. The value
# is the dotted path from the object root to the PodSpec.
_WORKLOAD_PODSPEC_PATH = {
    "Pod": "spec",
    "Deployment": "spec.template.spec",
    "ReplicaSet": "spec.template.spec",
    "StatefulSet": "spec.template.spec",
    "DaemonSet": "spec.template.spec",
    "Job": "spec.template.spec",
    "CronJob": "spec.jobTemplate.spec.template.spec",
    "ReplicationController": "spec.template.spec",
}


class PolicyError(ValueError):
    """Raised when a manifest or policy document cannot be parsed."""


# --------------------------------------------------------------------------
# Decision + report data model
# --------------------------------------------------------------------------

@dataclass
class Violation:
    """A single failed (or warned) policy rule against one object."""
    policy_id: str
    severity: str
    title: str
    control: str
    message: str
    action: str = "deny"          # deny | warn | mutate
    location: str = ""            # JSON pointer-ish path within the object
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Patch:
    """A JSONPatch operation emitted by a mutate policy."""
    op: str
    path: str
    value: Any = None
    policy_id: str = ""

    def to_jsonpatch(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"op": self.op, "path": self.path}
        if self.op in ("add", "replace", "test"):
            d["value"] = self.value
        return d


@dataclass
class Decision:
    """The verdict for one Kubernetes object."""
    kind: str
    name: str
    namespace: str = ""
    violations: List[Violation] = field(default_factory=list)
    patches: List[Patch] = field(default_factory=list)
    source: str = ""

    @property
    def deny_violations(self) -> List[Violation]:
        return [v for v in self.violations if v.action == "deny"]

    @property
    def warn_violations(self) -> List[Violation]:
        return [v for v in self.violations if v.action == "warn"]

    @property
    def allowed(self) -> bool:
        """An object is allowed unless a deny-action violation fired."""
        return not self.deny_violations

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for v in self.violations:
            c[v.severity] = c.get(v.severity, 0) + 1
        return c

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "namespace": self.namespace,
            "source": self.source,
            "allowed": self.allowed,
            "counts": self.counts,
            "violations": [v.to_dict() for v in self.violations],
            "patches": [p.to_jsonpatch() for p in self.patches],
        }


# --------------------------------------------------------------------------
# Manifest / AdmissionReview loading
# --------------------------------------------------------------------------

def _split_yaml_docs(text: str) -> List[str]:
    """Split a multi-document YAML stream on ``---`` separators."""
    docs: List[str] = []
    current: List[str] = []
    for line in text.splitlines():
        if line.strip() == "---":
            docs.append("\n".join(current))
            current = []
        else:
            current.append(line)
    docs.append("\n".join(current))
    return [d for d in docs if d.strip() and not _is_blank_or_comment(d)]


def _is_blank_or_comment(doc: str) -> bool:
    for line in doc.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            return False
    return True


def parse_objects(text: str, source: str = "<inline>") -> List[Tuple[Dict[str, Any], str]]:
    """Parse a manifest string into a list of (k8s object, source) tuples.

    Accepts:
      * a single JSON object,
      * a JSON array of objects,
      * a YAML-subset document (or multi-doc stream separated by ``---``),
      * an AdmissionReview wrapper (the embedded ``request.object`` is unwrapped).

    The YAML reader supports the subset used by Kubernetes manifests: mappings,
    block sequences (``- item``), nested indentation, scalars (string / int /
    float / bool / null), and inline ``[...]`` / ``{...}`` flow collections.
    """
    text = text.strip()
    if not text:
        return []

    # Try strict JSON first (covers AdmissionReview and JSON manifests).
    objs: List[Dict[str, Any]] = []
    try:
        data = json.loads(text)
        objs = _flatten_json_root(data)
    except json.JSONDecodeError:
        # Fall back to the YAML-subset reader, multi-doc aware.
        for doc in _split_yaml_docs(text):
            parsed = _parse_yaml_subset(doc)
            objs.extend(_flatten_json_root(parsed))

    out: List[Tuple[Dict[str, Any], str]] = []
    for o in objs:
        if isinstance(o, dict) and o:
            out.append((_unwrap_admission_review(o), source))
    return out


def _flatten_json_root(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        # A k8s List object.
        if data.get("kind") == "List" and isinstance(data.get("items"), list):
            return [d for d in data["items"] if isinstance(d, dict)]
        return [data]
    return []


def _unwrap_admission_review(obj: Dict[str, Any]) -> Dict[str, Any]:
    """If ``obj`` is an AdmissionReview, return the embedded request object."""
    if obj.get("kind") == "AdmissionReview":
        request = obj.get("request") or {}
        embedded = request.get("object")
        if isinstance(embedded, dict):
            # Stash the review uid so the webhook can echo it back.
            embedded.setdefault("__admission_uid__", request.get("uid"))
            return embedded
    return obj


def load_manifest_file(path: str) -> List[Tuple[Dict[str, Any], str]]:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return parse_objects(text, source=path)


# --------------------------------------------------------------------------
# Minimal YAML-subset reader (stdlib only — no PyYAML)
# --------------------------------------------------------------------------

def _parse_scalar(token: str) -> Any:
    t = token.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        return t[1:-1]
    # Inline flow collections.
    if (t.startswith("[") and t.endswith("]")) or (t.startswith("{") and t.endswith("}")):
        try:
            return json.loads(_flow_to_json(t))
        except (json.JSONDecodeError, ValueError):
            return t
    # Numbers.
    if re.fullmatch(r"-?\d+", t):
        try:
            return int(t)
        except ValueError:
            return t
    if re.fullmatch(r"-?\d*\.\d+", t):
        try:
            return float(t)
        except ValueError:
            return t
    return t


def _flow_to_json(t: str) -> str:
    """Best-effort conversion of YAML flow syntax to JSON for json.loads."""
    # Quote bare keys/values: turn { key: val } / [a, b] into JSON.
    out = []
    i = 0
    n = len(t)
    while i < n:
        ch = t[i]
        if ch in "{}[],:":
            out.append(ch)
            i += 1
            continue
        if ch in " \t":
            out.append(ch)
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            j = i + 1
            while j < n and t[j] != quote:
                j += 1
            out.append('"' + t[i + 1:j].replace('"', '\\"') + '"')
            i = j + 1
            continue
        # bare token until a structural char
        j = i
        while j < n and t[j] not in "{}[],:":
            j += 1
        tok = t[i:j].strip()
        if tok in ("true", "false", "null"):
            out.append(tok)
        elif re.fullmatch(r"-?\d+(\.\d+)?", tok):
            out.append(tok)
        elif tok == "":
            pass
        else:
            out.append('"' + tok.replace('"', '\\"') + '"')
        i = j
    return "".join(out)


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_yaml_subset(text: str) -> Any:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    # Strip trailing inline comments outside quotes (simple heuristic).
    cleaned: List[str] = []
    for ln in lines:
        cleaned.append(_strip_inline_comment(ln))
    value, _ = _parse_block(cleaned, 0, _indent_of(cleaned[0]) if cleaned else 0)
    return value


def _strip_inline_comment(line: str) -> str:
    in_s = False
    quote = ""
    for i, ch in enumerate(line):
        if in_s:
            if ch == quote:
                in_s = False
        elif ch in "\"'":
            in_s = True
            quote = ch
        elif ch == "#" and i > 0 and line[i - 1] in " \t":
            return line[:i].rstrip()
    return line.rstrip()


def _parse_block(lines: List[str], idx: int, indent: int) -> Tuple[Any, int]:
    """Parse a YAML block starting at lines[idx] with the given indent."""
    # Decide sequence vs mapping by peeking the first line at this indent.
    if idx >= len(lines):
        return None, idx
    first = lines[idx]
    if _indent_of(first) != indent:
        return None, idx
    if first.lstrip().startswith("- "):
        return _parse_sequence(lines, idx, indent)
    return _parse_mapping(lines, idx, indent)


def _parse_sequence(lines: List[str], idx: int, indent: int) -> Tuple[List[Any], int]:
    seq: List[Any] = []
    while idx < len(lines):
        line = lines[idx]
        cur = _indent_of(line)
        if cur < indent or not line.lstrip().startswith("- "):
            break
        if cur > indent:
            break
        content = line.lstrip()[2:]  # after "- "
        item_indent = cur + 2
        if ":" in content and not _looks_like_scalar(content):
            # Inline first key of a mapping item; reconstruct a virtual block.
            virtual = [" " * item_indent + content]
            j = idx + 1
            while j < len(lines) and _indent_of(lines[j]) >= item_indent:
                virtual.append(lines[j])
                j += 1
            val, _ = _parse_mapping(virtual, 0, item_indent)
            seq.append(val)
            idx = j
        elif content.strip() == "":
            # Nested block under the dash.
            j = idx + 1
            sub, j = _parse_block(lines, j, item_indent) if j < len(lines) and _indent_of(lines[j]) >= item_indent else (None, idx + 1)
            seq.append(sub)
            idx = j
        else:
            seq.append(_parse_scalar(content))
            idx += 1
    return seq, idx


def _looks_like_scalar(content: str) -> bool:
    # "- foo: bar" is a mapping; "- http://x" or "- ALL" is a scalar.
    key, _, rest = content.partition(":")
    if ":" not in content:
        return True
    # URL-ish (has :// ) → scalar
    if "://" in content:
        return True
    # key has spaces → treat as scalar
    if " " in key.strip():
        return True
    return False


def _parse_mapping(lines: List[str], idx: int, indent: int) -> Tuple[Dict[str, Any], int]:
    mapping: Dict[str, Any] = {}
    while idx < len(lines):
        line = lines[idx]
        cur = _indent_of(line)
        if cur != indent or line.lstrip().startswith("- "):
            break
        stripped = line.lstrip()
        key, sep, rest = stripped.partition(":")
        if not sep:
            break
        key = key.strip().strip('"\'')
        rest = rest.strip()
        if rest == "":
            # Value is a nested block on following deeper lines.
            j = idx + 1
            if j < len(lines) and _indent_of(lines[j]) > indent:
                child_indent = _indent_of(lines[j])
                if lines[j].lstrip().startswith("- ") and _indent_of(lines[j]) >= indent:
                    val, j = _parse_sequence(lines, j, child_indent)
                else:
                    val, j = _parse_block(lines, j, child_indent)
                mapping[key] = val
                idx = j
            else:
                mapping[key] = None
                idx += 1
        else:
            mapping[key] = _parse_scalar(rest)
            idx += 1
    return mapping, idx


# --------------------------------------------------------------------------
# Object navigation helpers
# --------------------------------------------------------------------------

def _dig(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _object_kind(obj: Dict[str, Any]) -> str:
    return str(obj.get("kind") or "")


def _object_name(obj: Dict[str, Any]) -> str:
    meta = obj.get("metadata") or {}
    return str(meta.get("name") or meta.get("generateName") or "<unnamed>")


def _object_namespace(obj: Dict[str, Any]) -> str:
    meta = obj.get("metadata") or {}
    return str(meta.get("namespace") or "")


def _pod_spec(obj: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], str]:
    """Return (podSpec, pointer_prefix) for a workload object, or (None, "")."""
    kind = _object_kind(obj)
    path = _WORKLOAD_PODSPEC_PATH.get(kind)
    if path is None:
        return None, ""
    spec = _dig(obj, path)
    if isinstance(spec, dict):
        pointer = "/" + path.replace(".", "/")
        return spec, pointer
    return None, ""


def _all_containers(pod_spec: Dict[str, Any]) -> List[Tuple[Dict[str, Any], str]]:
    """Return (container, kind) for every container in a PodSpec.

    ``kind`` is one of ``containers`` / ``initContainers`` / ``ephemeralContainers``.
    """
    out: List[Tuple[Dict[str, Any], str]] = []
    for group in ("initContainers", "containers", "ephemeralContainers"):
        for c in pod_spec.get(group) or []:
            if isinstance(c, dict):
                out.append((c, group))
    return out


# --------------------------------------------------------------------------
# Policy model + rule evaluation
# --------------------------------------------------------------------------

@dataclass
class Policy:
    id: str
    title: str
    severity: str
    control: str
    rules: List[Dict[str, Any]]
    action: str = "deny"           # deny | warn | mutate
    match_kinds: Optional[List[str]] = None
    source: str = "<builtin>"

    def applies_to(self, kind: str) -> bool:
        if not self.match_kinds:
            return kind in _WORKLOAD_PODSPEC_PATH
        return kind in self.match_kinds


def policy_from_dict(d: Dict[str, Any], source: str = "<loaded>") -> Policy:
    if not isinstance(d, dict):
        raise PolicyError("policy must be an object")
    pid = str(d.get("id") or "").strip()
    if not pid:
        raise PolicyError("policy is missing an 'id'")
    sev = str(d.get("severity") or "medium").strip().lower()
    if sev not in SEVERITY_ORDER:
        sev = "medium"
    action = str(d.get("action") or "deny").strip().lower()
    if action not in ("deny", "warn", "mutate"):
        action = "deny"
    rules = d.get("rules") or []
    if not isinstance(rules, list):
        raise PolicyError(f"policy {pid}: 'rules' must be a list")
    match = d.get("match") or {}
    kinds = match.get("kinds") if isinstance(match, dict) else None
    if kinds is not None and not isinstance(kinds, list):
        kinds = None
    return Policy(
        id=pid,
        title=str(d.get("title") or pid),
        severity=sev,
        control=str(d.get("control") or ""),
        rules=rules,
        action=action,
        match_kinds=kinds,
        source=source,
    )


def load_policies_dir(path: str) -> List[Policy]:
    """Load every ``.json`` / ``.yaml`` / ``.yml`` policy file under ``path``."""
    import os
    out: List[Policy] = []
    if os.path.isfile(path):
        files = [path]
    elif os.path.isdir(path):
        files = []
        for root, dirs, names in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for n in sorted(names):
                if n.lower().endswith((".json", ".yaml", ".yml")):
                    files.append(os.path.join(root, n))
    else:
        raise PolicyError(f"no such policy file or directory: {path}")

    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            text = fh.read()
        docs: List[Any] = []
        try:
            data = json.loads(text)
            docs = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            for d in _split_yaml_docs(text):
                docs.append(_parse_yaml_subset(d))
        for d in docs:
            if isinstance(d, dict) and d.get("policies") and isinstance(d["policies"], list):
                for p in d["policies"]:
                    out.append(policy_from_dict(p, source=f))
            elif isinstance(d, dict):
                out.append(policy_from_dict(d, source=f))
    return out


# ---- Rule verbs -----------------------------------------------------------
#
# Each rule is a dict with a single verb key. Supported verbs:
#
#   {"forbid_field": {"path": "securityContext.privileged", "equals": true}}
#       fire if any container has the field set to the given value (or just set).
#   {"require_field": {"path": "securityContext.runAsNonRoot", "equals": true}}
#       fire if any container is MISSING the field or it != equals.
#   {"forbid_pod_field": {"path": "hostNetwork", "equals": true}}
#       same as forbid_field but against the PodSpec, not each container.
#   {"require_pod_field": {"path": "..."}}
#   {"forbid_image_tag": {"tags": ["latest"], "untagged": true}}
#       fire on disallowed/implicit image tags.
#   {"require_registry": {"allowed": ["registry.internal/"]}}
#       fire if a container image is not from an allowed registry prefix.
#   {"require_drop_caps": {"caps": ["ALL"]}}
#       fire if a container does not drop the listed capabilities.
#   {"forbid_volume_type": {"types": ["hostPath"]}}
#       fire if the PodSpec mounts a forbidden volume type.
#   {"require_resource_limits": {"resources": ["cpu", "memory"]}}
#       fire if a container is missing resources.limits for the listed resources.


def _container_field(container: Dict[str, Any], path: str) -> Tuple[bool, Any]:
    """Return (present, value) for a dotted path within a container."""
    cur: Any = container
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _eval_rule(policy: Policy, rule: Dict[str, Any], obj: Dict[str, Any],
               pod_spec: Dict[str, Any], pointer: str) -> List[Violation]:
    if not isinstance(rule, dict) or len(rule) != 1:
        return []
    verb, spec = next(iter(rule.items()))
    spec = spec or {}
    handler = _RULE_KINDS.get(verb)
    if handler is None:
        return []
    return handler(policy, spec, obj, pod_spec, pointer)


def _mk(policy: Policy, message: str, location: str, remediation: str = "") -> Violation:
    return Violation(
        policy_id=policy.id,
        severity=policy.severity,
        title=policy.title,
        control=policy.control,
        message=message,
        action=policy.action,
        location=location,
        remediation=remediation,
    )


def _rule_forbid_field(policy, spec, obj, pod_spec, pointer):
    out: List[Violation] = []
    path = spec.get("path", "")
    want = spec.get("equals", "__any__")
    for idx, (c, group) in enumerate(_all_containers(pod_spec)):
        present, val = _container_field(c, path)
        if present and (want == "__any__" or val == want):
            cname = c.get("name", f"#{idx}")
            out.append(_mk(
                policy,
                f"container '{cname}' sets {path}"
                + (f"={json.dumps(val)}" if want != "__any__" else "")
                + " which is forbidden.",
                f"{pointer}/{group}/{idx}/{path.replace('.', '/')}",
                spec.get("remediation", f"Remove or unset {path}."),
            ))
    return out


def _rule_require_field(policy, spec, obj, pod_spec, pointer):
    out: List[Violation] = []
    path = spec.get("path", "")
    want = spec.get("equals", "__any__")
    for idx, (c, group) in enumerate(_all_containers(pod_spec)):
        present, val = _container_field(c, path)
        missing = (not present) or (want != "__any__" and val != want)
        if missing:
            cname = c.get("name", f"#{idx}")
            req = f"={json.dumps(want)}" if want != "__any__" else " to be set"
            out.append(_mk(
                policy,
                f"container '{cname}' must set {path}{req}.",
                f"{pointer}/{group}/{idx}/{path.replace('.', '/')}",
                spec.get("remediation", f"Set {path}{req}."),
            ))
    return out


def _rule_forbid_pod_field(policy, spec, obj, pod_spec, pointer):
    path = spec.get("path", "")
    want = spec.get("equals", "__any__")
    present, val = _container_field(pod_spec, path)
    if present and (want == "__any__" or val == want):
        return [_mk(
            policy,
            f"pod sets {path}" + (f"={json.dumps(val)}" if want != "__any__" else "")
            + " which is forbidden.",
            f"{pointer}/{path.replace('.', '/')}",
            spec.get("remediation", f"Remove or unset pod field {path}."),
        )]
    return []


def _rule_require_pod_field(policy, spec, obj, pod_spec, pointer):
    path = spec.get("path", "")
    want = spec.get("equals", "__any__")
    present, val = _container_field(pod_spec, path)
    missing = (not present) or (want != "__any__" and val != want)
    if missing:
        req = f"={json.dumps(want)}" if want != "__any__" else " to be set"
        return [_mk(
            policy,
            f"pod must set {path}{req}.",
            f"{pointer}/{path.replace('.', '/')}",
            spec.get("remediation", f"Set pod field {path}{req}."),
        )]
    return []


def _split_image(image: str) -> Tuple[str, str]:
    """Return (repo, tag). Digest pins ('@sha256:') count as a pinned tag."""
    image = str(image)
    if "@" in image:
        repo, _, digest = image.partition("@")
        return repo, digest
    # A ':' after the last '/' is the tag; ':' before is a registry port.
    last_slash = image.rfind("/")
    tail = image[last_slash + 1:]
    if ":" in tail:
        repo_tail, _, tag = tail.rpartition(":")
        repo = image[:last_slash + 1] + repo_tail
        return repo, tag
    return image, ""


def _rule_forbid_image_tag(policy, spec, obj, pod_spec, pointer):
    out: List[Violation] = []
    bad = {str(t).lower() for t in (spec.get("tags") or [])}
    flag_untagged = bool(spec.get("untagged", True))
    for idx, (c, group) in enumerate(_all_containers(pod_spec)):
        image = c.get("image")
        if not image:
            continue
        repo, tag = _split_image(image)
        cname = c.get("name", f"#{idx}")
        if not tag and flag_untagged:
            out.append(_mk(
                policy,
                f"container '{cname}' image '{image}' has no explicit tag "
                "(implicitly resolves to a mutable :latest).",
                f"{pointer}/{group}/{idx}/image",
                spec.get("remediation", "Pin the image to an immutable tag or digest."),
            ))
        elif tag.lower() in bad:
            out.append(_mk(
                policy,
                f"container '{cname}' image '{image}' uses forbidden tag ':{tag}'.",
                f"{pointer}/{group}/{idx}/image",
                spec.get("remediation", "Pin the image to an immutable tag or digest."),
            ))
    return out


def _rule_require_registry(policy, spec, obj, pod_spec, pointer):
    out: List[Violation] = []
    allowed = [str(a) for a in (spec.get("allowed") or [])]
    if not allowed:
        return out
    for idx, (c, group) in enumerate(_all_containers(pod_spec)):
        image = str(c.get("image") or "")
        if not image:
            continue
        if not any(image.startswith(a) for a in allowed):
            cname = c.get("name", f"#{idx}")
            out.append(_mk(
                policy,
                f"container '{cname}' image '{image}' is not from an allowed "
                f"registry ({', '.join(allowed)}).",
                f"{pointer}/{group}/{idx}/image",
                spec.get("remediation", "Use an image from an approved registry."),
            ))
    return out


def _rule_require_drop_caps(policy, spec, obj, pod_spec, pointer):
    out: List[Violation] = []
    need = {str(c).upper() for c in (spec.get("caps") or ["ALL"])}
    for idx, (c, group) in enumerate(_all_containers(pod_spec)):
        sc = c.get("securityContext") or {}
        caps = sc.get("capabilities") or {}
        dropped = {str(x).upper() for x in (caps.get("drop") or [])}
        cname = c.get("name", f"#{idx}")
        # Dropping ALL satisfies any specific requirement.
        if "ALL" in dropped:
            continue
        missing = need - dropped
        if missing:
            out.append(_mk(
                policy,
                f"container '{cname}' must drop capabilities {sorted(missing)}.",
                f"{pointer}/{group}/{idx}/securityContext/capabilities/drop",
                spec.get("remediation",
                         "Set securityContext.capabilities.drop to include "
                         + ", ".join(sorted(need)) + "."),
            ))
    return out


def _rule_forbid_volume_type(policy, spec, obj, pod_spec, pointer):
    out: List[Violation] = []
    bad = {str(t) for t in (spec.get("types") or [])}
    for idx, v in enumerate(pod_spec.get("volumes") or []):
        if not isinstance(v, dict):
            continue
        for vt in bad:
            if vt in v:
                out.append(_mk(
                    policy,
                    f"volume '{v.get('name', f'#{idx}')}' uses forbidden type "
                    f"'{vt}'.",
                    f"{pointer}/volumes/{idx}/{vt}",
                    spec.get("remediation", f"Do not mount {vt} volumes."),
                ))
    return out


def _rule_require_resource_limits(policy, spec, obj, pod_spec, pointer):
    out: List[Violation] = []
    needed = [str(r) for r in (spec.get("resources") or ["cpu", "memory"])]
    for idx, (c, group) in enumerate(_all_containers(pod_spec)):
        if group == "ephemeralContainers":
            continue
        limits = ((c.get("resources") or {}).get("limits")) or {}
        cname = c.get("name", f"#{idx}")
        missing = [r for r in needed if r not in limits]
        if missing:
            out.append(_mk(
                policy,
                f"container '{cname}' is missing resource limits for "
                f"{missing}.",
                f"{pointer}/{group}/{idx}/resources/limits",
                spec.get("remediation",
                         "Set resources.limits for " + ", ".join(needed) + "."),
            ))
    return out


_RULE_KINDS = {
    "forbid_field": _rule_forbid_field,
    "require_field": _rule_require_field,
    "forbid_pod_field": _rule_forbid_pod_field,
    "require_pod_field": _rule_require_pod_field,
    "forbid_image_tag": _rule_forbid_image_tag,
    "require_registry": _rule_require_registry,
    "require_drop_caps": _rule_require_drop_caps,
    "forbid_volume_type": _rule_forbid_volume_type,
    "require_resource_limits": _rule_require_resource_limits,
}


# --------------------------------------------------------------------------
# Mutation: synthesize JSONPatch from require_* rules (opt-in per policy)
# --------------------------------------------------------------------------

def _ensure_path_patches(pod_spec, pointer, group, idx, dotted, value) -> List[Patch]:
    """Build add/replace JSONPatch ops to set a container field to ``value``."""
    parts = dotted.split(".")
    container = pod_spec[group][idx] if group in pod_spec else {}
    cur = container
    built = f"{pointer}/{group}/{idx}"
    patches: List[Patch] = []
    for i, part in enumerate(parts):
        built += "/" + part
        if i == len(parts) - 1:
            op = "replace" if isinstance(cur, dict) and part in cur else "add"
            patches.append(Patch(op=op, path=built, value=value))
        else:
            if not (isinstance(cur, dict) and isinstance(cur.get(part), dict)):
                patches.append(Patch(op="add", path=built, value={}))
                cur = {}
            else:
                cur = cur[part]
    return patches


def _synthesize_patches(policy: Policy, obj, pod_spec, pointer) -> List[Patch]:
    """For a mutate policy, turn its require_* rules into JSONPatch ops."""
    patches: List[Patch] = []
    for rule in policy.rules:
        if not isinstance(rule, dict) or len(rule) != 1:
            continue
        verb, spec = next(iter(rule.items()))
        spec = spec or {}
        if verb == "require_field":
            path = spec.get("path", "")
            want = spec.get("equals", True)
            for idx, (c, group) in enumerate(_all_containers(pod_spec)):
                present, val = _container_field(c, path)
                if (not present) or val != want:
                    for p in _ensure_path_patches(pod_spec, pointer, group, idx, path, want):
                        p.policy_id = policy.id
                        patches.append(p)
        elif verb == "require_drop_caps":
            need = [str(x).upper() for x in (spec.get("caps") or ["ALL"])]
            for idx, (c, group) in enumerate(_all_containers(pod_spec)):
                sc = c.get("securityContext") or {}
                caps = sc.get("capabilities") or {}
                dropped = {str(x).upper() for x in (caps.get("drop") or [])}
                if "ALL" in dropped:
                    continue
                if set(need) - dropped:
                    p = Patch(op="add",
                              path=f"{pointer}/{group}/{idx}/securityContext/capabilities/drop",
                              value=need, policy_id=policy.id)
                    patches.append(p)
    return patches


# --------------------------------------------------------------------------
# Top-level evaluation
# --------------------------------------------------------------------------

def evaluate_object(obj: Dict[str, Any], policies: List[Policy],
                    source: str = "") -> Decision:
    """Evaluate a single Kubernetes object against ``policies``."""
    kind = _object_kind(obj)
    decision = Decision(
        kind=kind,
        name=_object_name(obj),
        namespace=_object_namespace(obj),
        source=source,
    )
    pod_spec, pointer = _pod_spec(obj)
    if pod_spec is None:
        return decision  # kind has no PodSpec → nothing to evaluate, allowed.

    for policy in policies:
        if not policy.applies_to(kind):
            continue
        if policy.action == "mutate":
            decision.patches.extend(_synthesize_patches(policy, obj, pod_spec, pointer))
            continue
        for rule in policy.rules:
            decision.violations.extend(
                _eval_rule(policy, rule, obj, pod_spec, pointer)
            )

    decision.violations.sort(key=lambda v: (SEVERITY_ORDER.get(v.severity, 99), v.policy_id))
    return decision


def evaluate_text(text: str, policies: List[Policy], source: str = "<inline>") -> List[Decision]:
    objs = parse_objects(text, source=source)
    return [evaluate_object(o, policies, source=src) for o, src in objs]


def evaluate_file(path: str, policies: List[Policy]) -> List[Decision]:
    objs = load_manifest_file(path)
    return [evaluate_object(o, policies, source=src) for o, src in objs]


# --------------------------------------------------------------------------
# Built-in policy library (original re-expression of public hardening guidance)
# --------------------------------------------------------------------------

def builtin_policies() -> List[Policy]:
    """Return the bundled hardening policy library.

    These map to widely published Kubernetes hardening concepts (CIS Kubernetes
    Benchmark, NSA/CISA Kubernetes Hardening Guidance). The rule definitions and
    wording are original Cognis work; no third-party policy text is reproduced.
    """
    defs: List[Dict[str, Any]] = [
        {
            "id": "ADMITD-PRIV-001",
            "title": "Deny privileged containers",
            "severity": "critical",
            "control": "NSA-CISA K8s Hardening: least privilege / CIS 5.2.1",
            "action": "deny",
            "rules": [{"forbid_field": {"path": "securityContext.privileged", "equals": True}}],
        },
        {
            "id": "ADMITD-PRIVESC-002",
            "title": "Deny privilege escalation",
            "severity": "high",
            "control": "NSA-CISA K8s Hardening: least privilege / CIS 5.2.5",
            "action": "deny",
            "rules": [{"forbid_field": {"path": "securityContext.allowPrivilegeEscalation", "equals": True}}],
        },
        {
            "id": "ADMITD-HOSTNS-003",
            "title": "Deny host namespaces (network / PID / IPC)",
            "severity": "high",
            "control": "NSA-CISA K8s Hardening: pod isolation / CIS 5.2.2-5.2.4",
            "action": "deny",
            "rules": [
                {"forbid_pod_field": {"path": "hostNetwork", "equals": True}},
                {"forbid_pod_field": {"path": "hostPID", "equals": True}},
                {"forbid_pod_field": {"path": "hostIPC", "equals": True}},
            ],
        },
        {
            "id": "ADMITD-HOSTPATH-004",
            "title": "Deny hostPath volumes",
            "severity": "high",
            "control": "NSA-CISA K8s Hardening: volume isolation / CIS 5.2.x",
            "action": "deny",
            "rules": [{"forbid_volume_type": {"types": ["hostPath"]}}],
        },
        {
            "id": "ADMITD-NONROOT-005",
            "title": "Require runAsNonRoot",
            "severity": "high",
            "control": "NSA-CISA K8s Hardening: non-root containers / CIS 5.2.6",
            "action": "deny",
            "rules": [{"require_field": {"path": "securityContext.runAsNonRoot", "equals": True}}],
        },
        {
            "id": "ADMITD-ROFS-006",
            "title": "Require read-only root filesystem",
            "severity": "medium",
            "control": "NSA-CISA K8s Hardening: immutable runtime / CIS 5.2.x",
            "action": "deny",
            "rules": [{"require_field": {"path": "securityContext.readOnlyRootFilesystem", "equals": True}}],
        },
        {
            "id": "ADMITD-DROPCAPS-007",
            "title": "Require dropping ALL Linux capabilities",
            "severity": "medium",
            "control": "NSA-CISA K8s Hardening: capability reduction / CIS 5.2.7-5.2.9",
            "action": "deny",
            "rules": [{"require_drop_caps": {"caps": ["ALL"]}}],
        },
        {
            "id": "ADMITD-LATEST-008",
            "title": "Deny :latest / untagged images",
            "severity": "medium",
            "control": "Supply-chain integrity: immutable image references",
            "action": "deny",
            "rules": [{"forbid_image_tag": {"tags": ["latest"], "untagged": True}}],
        },
        {
            "id": "ADMITD-LIMITS-009",
            "title": "Require CPU and memory limits",
            "severity": "low",
            "control": "Resource governance / DoS resistance / CIS 5.x",
            "action": "deny",
            "rules": [{"require_resource_limits": {"resources": ["cpu", "memory"]}}],
        },
        {
            "id": "ADMITD-SECCOMP-010",
            "title": "Require a seccomp profile (RuntimeDefault or Localhost)",
            "severity": "medium",
            "control": "NSA-CISA K8s Hardening: syscall reduction",
            "action": "deny",
            "rules": [{"require_field": {"path": "securityContext.seccompProfile.type", "equals": "RuntimeDefault"}}],
        },
    ]
    return [policy_from_dict(d, source="<builtin>") for d in defs]


def all_policies(extra_dir: Optional[str] = None,
                 include_builtin: bool = True) -> List[Policy]:
    pols: List[Policy] = list(builtin_policies()) if include_builtin else []
    if extra_dir:
        pols.extend(load_policies_dir(extra_dir))
    return pols


# --------------------------------------------------------------------------
# Serializers
# --------------------------------------------------------------------------

def decisions_to_dict(decisions: List[Decision]) -> Dict[str, Any]:
    agg = {k: 0 for k in SEVERITY_ORDER}
    for d in decisions:
        for sev, n in d.counts.items():
            agg[sev] += n
    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "objects_evaluated": len(decisions),
        "objects_denied": sum(1 for d in decisions if not d.allowed),
        "total_violations": sum(len(d.violations) for d in decisions),
        "counts": agg,
        "allowed": all(d.allowed for d in decisions),
        "decisions": [d.to_dict() for d in decisions],
    }


_SARIF_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}


def _security_severity(sev: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.0",
            "low": "3.0", "info": "0.0"}.get(sev, "5.0")


def to_sarif(decisions: List[Decision]) -> Dict[str, Any]:
    """Render decisions as a SARIF 2.1.0 log (GitHub code-scanning ready)."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for d in decisions:
        for v in d.violations:
            if v.policy_id not in rules:
                rules[v.policy_id] = {
                    "id": v.policy_id,
                    "name": v.policy_id,
                    "shortDescription": {"text": v.title},
                    "fullDescription": {"text": (v.control or v.title)},
                    "defaultConfiguration": {"level": _SARIF_LEVEL.get(v.severity, "warning")},
                    "properties": {"security-severity": _security_severity(v.severity)},
                }
            results.append({
                "ruleId": v.policy_id,
                "level": _SARIF_LEVEL.get(v.severity, "warning"),
                "message": {"text": v.message
                            + (f"\nRemediation: {v.remediation}" if v.remediation else "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": (d.source or d.name).replace("\\", "/")},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"fullyQualifiedName": v.location or f"{d.kind}/{d.name}"}],
                }],
                "properties": {"severity": v.severity, "control": v.control,
                               "object": f"{d.kind}/{d.name}", "action": v.action},
            })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/admitd",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def _xml_escape(text: str, attr: bool = False) -> str:
    out = (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    if attr:
        out = out.replace('"', "&quot;")
    return out


def to_junit(decisions: List[Decision]) -> str:
    """Render decisions as a JUnit XML report.

    Each evaluated object becomes a ``<testcase>``; every violation on it becomes
    a nested ``<failure>``. CI systems that consume JUnit XML (GitLab, Jenkins,
    Azure DevOps, CircleCI, Buildkite) can then surface admitd findings in the
    same test-report pane as unit tests — one object = one test, each broken
    control = one failure line. An object with no violations is a passing test.

    The output is deterministic and stdlib-only (no XML library required).
    """
    total_failures = sum(len(d.violations) for d in decisions)
    lines: List[str] = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(
        '<testsuites name="{name}" tests="{tests}" failures="{fails}">'.format(
            name=_xml_escape(f"{TOOL_NAME} admission", attr=True),
            tests=len(decisions),
            fails=total_failures,
        )
    )
    lines.append(
        '  <testsuite name="{name}" tests="{tests}" failures="{fails}">'.format(
            name=_xml_escape(f"{TOOL_NAME} {TOOL_VERSION}", attr=True),
            tests=len(decisions),
            fails=total_failures,
        )
    )
    for d in decisions:
        classname = _xml_escape(f"{d.namespace or 'cluster'}.{d.kind}", attr=True)
        casename = _xml_escape(d.name, attr=True)
        if not d.violations:
            lines.append(
                f'    <testcase classname="{classname}" name="{casename}"/>'
            )
            continue
        lines.append(f'    <testcase classname="{classname}" name="{casename}">')
        for v in d.violations:
            msg = _xml_escape(f"[{v.policy_id}] {v.title}", attr=True)
            body_parts = [v.message]
            if v.control:
                body_parts.append(f"control: {v.control}")
            if v.location:
                body_parts.append(f"at: {v.location}")
            if v.remediation:
                body_parts.append(f"fix: {v.remediation}")
            body = _xml_escape("\n".join(body_parts))
            ftype = _xml_escape(f"{v.severity}/{v.action}", attr=True)
            lines.append(f'      <failure message="{msg}" type="{ftype}">{body}</failure>')
        lines.append("    </testcase>")
    lines.append("  </testsuite>")
    lines.append("</testsuites>")
    return "\n".join(lines)


def admission_response(decision: Decision, uid: str = "") -> Dict[str, Any]:
    """Build a Kubernetes AdmissionReview response for one decision.

    If the decision is allowed and has mutation patches, those are returned as a
    base64-encoded JSONPatch in the standard webhook shape.
    """
    import base64
    allowed = decision.allowed
    status_msg = ""
    if not allowed:
        reasons = "; ".join(f"[{v.policy_id}] {v.message}" for v in decision.deny_violations)
        status_msg = f"{TOOL_NAME} denied {decision.kind}/{decision.name}: {reasons}"

    response: Dict[str, Any] = {
        "uid": uid or decision_uid(decision),
        "allowed": allowed,
    }
    if status_msg:
        response["status"] = {"code": 403, "message": status_msg}
    if allowed and decision.patches:
        patch = [p.to_jsonpatch() for p in decision.patches]
        response["patchType"] = "JSONPatch"
        response["patch"] = base64.b64encode(
            json.dumps(patch).encode("utf-8")
        ).decode("ascii")
    if decision.warn_violations:
        response["warnings"] = [
            f"[{v.policy_id}] {v.message}" for v in decision.warn_violations
        ]
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": response,
    }


def decision_uid(decision: Decision) -> str:
    h = hashlib.sha256(f"{decision.kind}/{decision.namespace}/{decision.name}".encode()).hexdigest()
    return h[:16]
