"""Opt-in AI policy drafting for admitd.

OFF BY DEFAULT. This thin wrapper reuses the Cognis shared AI backend
(``admitd._ai_backend``) — the same env-driven, local-fleet, OpenAI-compatible
client every Cognis tool ships — to turn a plain-English rule description into a
*draft* admitd policy document.

Nothing leaves the box: it only talks to a LOCAL endpoint you explicitly
configure via ``COGNIS_AI_BACKEND`` / ``COGNIS_AI_ENDPOINT``. With no
configuration ``is_enabled()`` is ``False`` and ``draft_policy`` returns ``None``
so the CLI degrades gracefully. The output is always run back through
``policy_from_dict`` so a malformed draft can never become an executable policy.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from admitd import _ai_backend
from admitd.core import SEVERITY_ORDER, Policy, policy_from_dict, _RULE_KINDS

_SYSTEM_PROMPT = (
    "You are a Kubernetes security policy author for the admitd admission "
    "engine. Given a plain-English rule, emit ONE admitd policy as a STRICT "
    "JSON object (and nothing else) with exactly these keys: "
    '"id" (uppercase slug like "ADMITD-CUSTOM-001"), "title" (short string), '
    '"severity" (one of critical|high|medium|low|info), "control" (the public '
    'hardening control it maps to, or ""), "action" (deny|warn|mutate), '
    'and "rules" (a non-empty array). Each rule is an object with EXACTLY ONE '
    "of these verb keys, matching admitd's schema:\n"
    '  {"forbid_field": {"path": "securityContext.privileged", "equals": true}}\n'
    '  {"require_field": {"path": "securityContext.runAsNonRoot", "equals": true}}\n'
    '  {"forbid_pod_field": {"path": "hostNetwork", "equals": true}}\n'
    '  {"require_pod_field": {"path": "..."}}\n'
    '  {"forbid_image_tag": {"tags": ["latest"], "untagged": true}}\n'
    '  {"require_registry": {"allowed": ["registry.internal/"]}}\n'
    '  {"require_drop_caps": {"caps": ["ALL"]}}\n'
    '  {"forbid_volume_type": {"types": ["hostPath"]}}\n'
    '  {"require_resource_limits": {"resources": ["cpu","memory"]}}\n'
    "Use ONLY these verbs. Output the JSON object only — no prose, no fences."
)


def is_enabled() -> bool:
    return _ai_backend.is_enabled()


def health() -> bool:
    return _ai_backend.health()


def draft_policy(description: str, suggested_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Draft a policy dict from a plain-English description, or None.

    Returns ``None`` when the backend is disabled, unreachable, or produces an
    output that cannot be coerced into a valid admitd policy.
    """
    if not is_enabled():
        return None
    description = (description or "").strip()
    if not description:
        return None

    backend = _ai_backend.CognisAIBackend()
    user = (
        "Plain-English rule to implement:\n" + description
        + (f"\n\nUse this policy id: {suggested_id}" if suggested_id else "")
    )
    try:
        content = backend._chat(_SYSTEM_PROMPT, user)  # noqa: SLF001 (reuse plumbing)
    except Exception:
        return None
    if not content:
        return None

    obj = _extract_object(content)
    if obj is None:
        return None

    obj = _sanitize(obj, suggested_id)
    try:
        policy_from_dict(obj)  # validate it is a real, runnable policy
    except Exception:
        return None
    return obj


def _extract_object(text: str) -> Optional[Dict[str, Any]]:
    """Pull the first balanced top-level JSON object from model output."""
    text = _ai_backend.CognisAIBackend._strip_think(text)  # noqa: SLF001
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _sanitize(obj: Dict[str, Any], suggested_id: Optional[str]) -> Dict[str, Any]:
    """Normalize an AI-drafted object and drop unknown rule verbs."""
    out: Dict[str, Any] = {}
    out["id"] = str(obj.get("id") or suggested_id or "ADMITD-CUSTOM-001").strip()
    out["title"] = str(obj.get("title") or out["id"]).strip()
    sev = str(obj.get("severity") or "medium").strip().lower()
    out["severity"] = sev if sev in SEVERITY_ORDER else "medium"
    out["control"] = str(obj.get("control") or "AI-drafted (review before use)").strip()
    action = str(obj.get("action") or "deny").strip().lower()
    out["action"] = action if action in ("deny", "warn", "mutate") else "deny"

    rules = obj.get("rules") or []
    clean_rules = []
    if isinstance(rules, list):
        for r in rules:
            if isinstance(r, dict) and len(r) == 1:
                verb = next(iter(r))
                if verb in _RULE_KINDS and isinstance(r[verb], dict):
                    clean_rules.append(r)
    out["rules"] = clean_rules
    if obj.get("match"):
        out["match"] = obj["match"]
    return out
