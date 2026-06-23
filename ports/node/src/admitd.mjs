// admitd — Node / TypeScript-friendly port of the Kubernetes policy-as-code
// admission engine. Mirrors the core surface of the primary Python CLI:
// the built-in CIS / NSA-CISA hardening policy library, single-object
// evaluation, and an allow/deny decision rendered as JSON.
//
// Pure ES modules, zero dependencies, deterministic, and fully offline — no
// network access of any kind. Importable as a library or run via the bundled
// `cli.mjs`.
//
// Type information is provided through JSDoc so this file is usable directly
// from TypeScript (with `checkJs`/`allowJs`) as well as plain Node.

export const TOOL_NAME = "admitd";
export const TOOL_VERSION = "0.1.0";

/** @type {Record<string, number>} */
export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** @type {Record<string, string>} */
const WORKLOAD_PODSPEC_PATH = {
  Pod: "spec",
  Deployment: "spec.template.spec",
  ReplicaSet: "spec.template.spec",
  StatefulSet: "spec.template.spec",
  DaemonSet: "spec.template.spec",
  Job: "spec.template.spec",
  CronJob: "spec.jobTemplate.spec.template.spec",
  ReplicationController: "spec.template.spec",
};

/**
 * @typedef {Object} Violation
 * @property {string} policy_id
 * @property {string} severity
 * @property {string} title
 * @property {string} control
 * @property {string} message
 * @property {string} action
 * @property {string} location
 * @property {string} remediation
 */

/**
 * @typedef {Object} Policy
 * @property {string} id
 * @property {string} title
 * @property {string} severity
 * @property {string} control
 * @property {string} action
 * @property {string[]|null} [matchKinds]
 * @property {Array<Record<string, any>>} rules
 */

function dig(obj, dotted) {
  let cur = obj;
  for (const part of dotted.split(".")) {
    if (!part) continue;
    if (cur && typeof cur === "object" && !Array.isArray(cur) && part in cur) {
      cur = cur[part];
    } else {
      return [false, undefined];
    }
  }
  return [true, cur];
}

function objectKind(o) { return String((o && o.kind) || ""); }
function objectName(o) {
  const m = (o && o.metadata) || {};
  return String(m.name || m.generateName || "<unnamed>");
}
function objectNamespace(o) {
  const m = (o && o.metadata) || {};
  return String(m.namespace || "");
}

function podSpec(o) {
  const path = WORKLOAD_PODSPEC_PATH[objectKind(o)];
  if (!path) return [null, ""];
  const [found, spec] = dig(o, path);
  if (!found || typeof spec !== "object" || spec === null || Array.isArray(spec)) return [null, ""];
  return [spec, "/" + path.replace(/\./g, "/")];
}

function allContainers(ps) {
  const out = [];
  for (const group of ["initContainers", "containers", "ephemeralContainers"]) {
    const list = ps[group] || [];
    if (Array.isArray(list)) {
      list.forEach((c, idx) => {
        if (c && typeof c === "object") out.push({ c, group, idx });
      });
    }
  }
  return out;
}

function containerField(c, path) {
  let cur = c;
  for (const part of path.split(".")) {
    if (cur && typeof cur === "object" && !Array.isArray(cur) && part in cur) cur = cur[part];
    else return [false, undefined];
  }
  return [true, cur];
}

function cname(cr) {
  return (cr.c && cr.c.name) || `#${cr.idx}`;
}

/** @returns {[string, string]} */
export function splitImage(image) {
  image = String(image);
  const at = image.indexOf("@");
  if (at >= 0) return [image.slice(0, at), image.slice(at + 1)];
  const lastSlash = image.lastIndexOf("/");
  const tail = image.slice(lastSlash + 1);
  const colon = tail.lastIndexOf(":");
  if (colon >= 0) return [image.slice(0, lastSlash + 1) + tail.slice(0, colon), tail.slice(colon + 1)];
  return [image, ""];
}

function mk(p, message, location, remediation) {
  return {
    policy_id: p.id, severity: p.severity, title: p.title, control: p.control,
    message, action: p.action, location, remediation,
  };
}

function jsonEq(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

const RULE_HANDLERS = {
  forbid_field(p, spec, ps, ptr) {
    const out = [];
    const path = spec.path || "";
    const hasWant = "equals" in spec;
    for (const cr of allContainers(ps)) {
      const [present, val] = containerField(cr.c, path);
      if (present && (!hasWant || jsonEq(val, spec.equals))) {
        const suffix = hasWant ? `=${JSON.stringify(val)}` : "";
        out.push(mk(p, `container '${cname(cr)}' sets ${path}${suffix} which is forbidden.`,
          `${ptr}/${cr.group}/${cr.idx}/${path.replace(/\./g, "/")}`,
          spec.remediation || `Remove or unset ${path}.`));
      }
    }
    return out;
  },
  require_field(p, spec, ps, ptr) {
    const out = [];
    const path = spec.path || "";
    const hasWant = "equals" in spec;
    for (const cr of allContainers(ps)) {
      const [present, val] = containerField(cr.c, path);
      if (!present || (hasWant && !jsonEq(val, spec.equals))) {
        out.push(mk(p, `container '${cname(cr)}' must set ${path}.`,
          `${ptr}/${cr.group}/${cr.idx}/${path.replace(/\./g, "/")}`,
          spec.remediation || `Set ${path}.`));
      }
    }
    return out;
  },
  forbid_pod_field(p, spec, ps, ptr) {
    const path = spec.path || "";
    const hasWant = "equals" in spec;
    const [present, val] = containerField(ps, path);
    if (present && (!hasWant || jsonEq(val, spec.equals))) {
      return [mk(p, `pod sets ${path} which is forbidden.`,
        `${ptr}/${path.replace(/\./g, "/")}`,
        spec.remediation || `Remove or unset pod field ${path}.`)];
    }
    return [];
  },
  require_pod_field(p, spec, ps, ptr) {
    const path = spec.path || "";
    const hasWant = "equals" in spec;
    const [present, val] = containerField(ps, path);
    if (!present || (hasWant && !jsonEq(val, spec.equals))) {
      return [mk(p, `pod must set ${path}.`,
        `${ptr}/${path.replace(/\./g, "/")}`,
        spec.remediation || `Set pod field ${path}.`)];
    }
    return [];
  },
  forbid_image_tag(p, spec, ps, ptr) {
    const out = [];
    const bad = new Set((spec.tags || []).map((t) => String(t).toLowerCase()));
    const flagUntagged = spec.untagged !== false;
    for (const cr of allContainers(ps)) {
      const image = cr.c.image;
      if (!image) continue;
      const [, tag] = splitImage(image);
      if (!tag && flagUntagged) {
        out.push(mk(p, `container '${cname(cr)}' image '${image}' has no explicit tag (implicitly resolves to a mutable :latest).`,
          `${ptr}/${cr.group}/${cr.idx}/image`,
          spec.remediation || "Pin the image to an immutable tag or digest."));
      } else if (bad.has(tag.toLowerCase())) {
        out.push(mk(p, `container '${cname(cr)}' image '${image}' uses forbidden tag ':${tag}'.`,
          `${ptr}/${cr.group}/${cr.idx}/image`,
          spec.remediation || "Pin the image to an immutable tag or digest."));
      }
    }
    return out;
  },
  require_registry(p, spec, ps, ptr) {
    const out = [];
    const allowed = (spec.allowed || []).map(String);
    if (allowed.length === 0) return out;
    for (const cr of allContainers(ps)) {
      const image = String(cr.c.image || "");
      if (!image) continue;
      if (!allowed.some((a) => image.startsWith(a))) {
        out.push(mk(p, `container '${cname(cr)}' image '${image}' is not from an allowed registry (${allowed.join(", ")}).`,
          `${ptr}/${cr.group}/${cr.idx}/image`,
          spec.remediation || "Use an image from an approved registry."));
      }
    }
    return out;
  },
  require_drop_caps(p, spec, ps, ptr) {
    const out = [];
    const need = (spec.caps || ["ALL"]).map((c) => String(c).toUpperCase());
    for (const cr of allContainers(ps)) {
      const sc = cr.c.securityContext || {};
      const caps = sc.capabilities || {};
      const dropped = new Set((caps.drop || []).map((x) => String(x).toUpperCase()));
      if (dropped.has("ALL")) continue;
      const missing = need.filter((n) => !dropped.has(n)).sort();
      if (missing.length) {
        out.push(mk(p, `container '${cname(cr)}' must drop capabilities [${missing.map((m) => `'${m}'`).join(", ")}].`,
          `${ptr}/${cr.group}/${cr.idx}/securityContext/capabilities/drop`,
          spec.remediation || "Drop the required Linux capabilities."));
      }
    }
    return out;
  },
  forbid_volume_type(p, spec, ps, ptr) {
    const out = [];
    const bad = (spec.types || []).map(String);
    (ps.volumes || []).forEach((v, idx) => {
      if (!v || typeof v !== "object") return;
      for (const vt of bad) {
        if (vt in v) {
          out.push(mk(p, `volume '${v.name || `#${idx}`}' uses forbidden type '${vt}'.`,
            `${ptr}/volumes/${idx}/${vt}`,
            spec.remediation || `Do not mount ${vt} volumes.`));
        }
      }
    });
    return out;
  },
  require_resource_limits(p, spec, ps, ptr) {
    const out = [];
    const needed = (spec.resources || ["cpu", "memory"]).map(String);
    for (const cr of allContainers(ps)) {
      if (cr.group === "ephemeralContainers") continue;
      const limits = ((cr.c.resources || {}).limits) || {};
      const missing = needed.filter((r) => !(r in limits));
      if (missing.length) {
        out.push(mk(p, `container '${cname(cr)}' is missing resource limits for [${missing.map((m) => `'${m}'`).join(", ")}].`,
          `${ptr}/${cr.group}/${cr.idx}/resources/limits`,
          spec.remediation || "Set resources.limits."));
      }
    }
    return out;
  },
};

function appliesTo(p, kind) {
  if (!p.matchKinds || p.matchKinds.length === 0) return kind in WORKLOAD_PODSPEC_PATH;
  return p.matchKinds.includes(kind);
}

/**
 * Evaluate a single Kubernetes object against the given policies.
 * @param {Record<string, any>} obj
 * @param {Policy[]} policies
 * @param {string} [source]
 */
export function evaluateObject(obj, policies, source = "") {
  const kind = objectKind(obj);
  const decision = {
    kind, name: objectName(obj), namespace: objectNamespace(obj), source,
    violations: /** @type {Violation[]} */ ([]),
  };
  const [ps, ptr] = podSpec(obj);
  if (!ps) return decisionView(decision);
  for (const p of policies) {
    if (!appliesTo(p, kind) || p.action === "mutate") continue;
    for (const rule of p.rules) {
      for (const [verb, spec] of Object.entries(rule)) {
        const h = RULE_HANDLERS[verb];
        if (h) decision.violations.push(...h(p, spec || {}, ps, ptr));
      }
    }
  }
  decision.violations.sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 99, sb = SEVERITY_ORDER[b.severity] ?? 99;
    return sa !== sb ? sa - sb : a.policy_id.localeCompare(b.policy_id);
  });
  return decisionView(decision);
}

function decisionView(d) {
  const denyViolations = () => d.violations.filter((v) => v.action === "deny");
  return {
    ...d,
    denyViolations,
    get allowed() { return denyViolations().length === 0; },
    counts() {
      const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const v of d.violations) c[v.severity] = (c[v.severity] || 0) + 1;
      return c;
    },
    toDict() {
      return {
        kind: d.kind, name: d.name, namespace: d.namespace, source: d.source,
        allowed: this.allowed, counts: this.counts(),
        violations: d.violations, patches: [],
      };
    },
  };
}

function unwrapAdmissionReview(o) {
  if (objectKind(o) === "AdmissionReview") {
    const req = o.request || {};
    if (req.object && typeof req.object === "object") return req.object;
  }
  return o;
}

/**
 * Parse a JSON manifest, JSON array, k8s List, or AdmissionReview into objects.
 * @param {string} text
 * @returns {Record<string, any>[]}
 */
export function parseObjects(text) {
  const data = JSON.parse(text);
  let objs = [];
  if (Array.isArray(data)) objs = data.filter((d) => d && typeof d === "object");
  else if (data && data.kind === "List" && Array.isArray(data.items)) objs = data.items;
  else if (data && typeof data === "object") objs = [data];
  return objs.map(unwrapAdmissionReview);
}

const rule = (verb, kv) => ({ [verb]: kv });

/** @returns {Policy[]} */
export function builtinPolicies() {
  return [
    { id: "ADMITD-PRIV-001", title: "Deny privileged containers", severity: "critical",
      control: "NSA-CISA K8s Hardening: least privilege / CIS 5.2.1", action: "deny",
      rules: [rule("forbid_field", { path: "securityContext.privileged", equals: true })] },
    { id: "ADMITD-PRIVESC-002", title: "Deny privilege escalation", severity: "high",
      control: "NSA-CISA K8s Hardening: least privilege / CIS 5.2.5", action: "deny",
      rules: [rule("forbid_field", { path: "securityContext.allowPrivilegeEscalation", equals: true })] },
    { id: "ADMITD-HOSTNS-003", title: "Deny host namespaces (network / PID / IPC)", severity: "high",
      control: "NSA-CISA K8s Hardening: pod isolation / CIS 5.2.2-5.2.4", action: "deny",
      rules: [
        rule("forbid_pod_field", { path: "hostNetwork", equals: true }),
        rule("forbid_pod_field", { path: "hostPID", equals: true }),
        rule("forbid_pod_field", { path: "hostIPC", equals: true }),
      ] },
    { id: "ADMITD-HOSTPATH-004", title: "Deny hostPath volumes", severity: "high",
      control: "NSA-CISA K8s Hardening: volume isolation / CIS 5.2.x", action: "deny",
      rules: [rule("forbid_volume_type", { types: ["hostPath"] })] },
    { id: "ADMITD-NONROOT-005", title: "Require runAsNonRoot", severity: "high",
      control: "NSA-CISA K8s Hardening: non-root containers / CIS 5.2.6", action: "deny",
      rules: [rule("require_field", { path: "securityContext.runAsNonRoot", equals: true })] },
    { id: "ADMITD-ROFS-006", title: "Require read-only root filesystem", severity: "medium",
      control: "NSA-CISA K8s Hardening: immutable runtime / CIS 5.2.x", action: "deny",
      rules: [rule("require_field", { path: "securityContext.readOnlyRootFilesystem", equals: true })] },
    { id: "ADMITD-DROPCAPS-007", title: "Require dropping ALL Linux capabilities", severity: "medium",
      control: "NSA-CISA K8s Hardening: capability reduction / CIS 5.2.7-5.2.9", action: "deny",
      rules: [rule("require_drop_caps", { caps: ["ALL"] })] },
    { id: "ADMITD-LATEST-008", title: "Deny :latest / untagged images", severity: "medium",
      control: "Supply-chain integrity: immutable image references", action: "deny",
      rules: [rule("forbid_image_tag", { tags: ["latest"], untagged: true })] },
    { id: "ADMITD-LIMITS-009", title: "Require CPU and memory limits", severity: "low",
      control: "Resource governance / DoS resistance / CIS 5.x", action: "deny",
      rules: [rule("require_resource_limits", { resources: ["cpu", "memory"] })] },
    { id: "ADMITD-SECCOMP-010", title: "Require a seccomp profile (RuntimeDefault or Localhost)", severity: "medium",
      control: "NSA-CISA K8s Hardening: syscall reduction", action: "deny",
      rules: [rule("require_field", { path: "securityContext.seccompProfile.type", equals: "RuntimeDefault" })] },
  ];
}

/**
 * Evaluate objects in a manifest string and return the aggregate report dict.
 * @param {string} text
 * @param {string} [source]
 */
export function evaluateText(text, source = "<inline>") {
  const policies = builtinPolicies();
  const decisions = parseObjects(text).map((o) => evaluateObject(o, policies, source));
  return {
    tool: TOOL_NAME, version: TOOL_VERSION,
    objects_evaluated: decisions.length,
    objects_denied: decisions.filter((d) => !d.allowed).length,
    total_violations: decisions.reduce((n, d) => n + d.violations.length, 0),
    allowed: decisions.every((d) => d.allowed),
    decisions: decisions.map((d) => d.toDict()),
  };
}
