//! admitd — Rust port of the Kubernetes policy-as-code admission engine.
//!
//! Mirrors the core surface of the primary Python CLI: the built-in CIS /
//! NSA-CISA hardening policy library, single-object evaluation, and an
//! allow/deny decision. Dependency-free (standard library + a bundled JSON
//! reader), deterministic, and fully offline — no network access of any kind.

pub mod json;

use json::Json;
use std::collections::BTreeMap;

pub const TOOL_NAME: &str = "admitd";
pub const TOOL_VERSION: &str = "0.1.0";

fn severity_rank(sev: &str) -> u8 {
    match sev {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn podspec_path(kind: &str) -> Option<&'static str> {
    match kind {
        "Pod" => Some("spec"),
        "Deployment" | "ReplicaSet" | "StatefulSet" | "DaemonSet" | "Job"
        | "ReplicationController" => Some("spec.template.spec"),
        "CronJob" => Some("spec.jobTemplate.spec.template.spec"),
        _ => None,
    }
}

/// A single failed (or warned) policy rule.
#[derive(Debug, Clone)]
pub struct Violation {
    pub policy_id: String,
    pub severity: String,
    pub title: String,
    pub control: String,
    pub message: String,
    pub action: String,
    pub location: String,
    pub remediation: String,
}

/// The verdict for one object.
#[derive(Debug, Clone)]
pub struct Decision {
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub source: String,
    pub violations: Vec<Violation>,
}

impl Decision {
    pub fn deny_violations(&self) -> Vec<&Violation> {
        self.violations.iter().filter(|v| v.action == "deny").collect()
    }
    pub fn allowed(&self) -> bool {
        self.deny_violations().is_empty()
    }
    pub fn to_json(&self) -> Json {
        let mut counts: BTreeMap<String, Json> = BTreeMap::new();
        for s in ["critical", "high", "medium", "low", "info"] {
            counts.insert(s.to_string(), Json::Num(0.0));
        }
        for v in &self.violations {
            let n = if let Some(Json::Num(x)) = counts.get(&v.severity) { *x } else { 0.0 };
            counts.insert(v.severity.clone(), Json::Num(n + 1.0));
        }
        let mut obj = BTreeMap::new();
        obj.insert("kind".into(), Json::Str(self.kind.clone()));
        obj.insert("name".into(), Json::Str(self.name.clone()));
        obj.insert("namespace".into(), Json::Str(self.namespace.clone()));
        obj.insert("source".into(), Json::Str(self.source.clone()));
        obj.insert("allowed".into(), Json::Bool(self.allowed()));
        obj.insert("counts".into(), Json::Obj(counts));
        obj.insert(
            "violations".into(),
            Json::Arr(self.violations.iter().map(violation_json).collect()),
        );
        obj.insert("patches".into(), Json::Arr(vec![]));
        Json::Obj(obj)
    }
}

fn violation_json(v: &Violation) -> Json {
    let mut o = BTreeMap::new();
    o.insert("policy_id".into(), Json::Str(v.policy_id.clone()));
    o.insert("severity".into(), Json::Str(v.severity.clone()));
    o.insert("title".into(), Json::Str(v.title.clone()));
    o.insert("control".into(), Json::Str(v.control.clone()));
    o.insert("message".into(), Json::Str(v.message.clone()));
    o.insert("action".into(), Json::Str(v.action.clone()));
    o.insert("location".into(), Json::Str(v.location.clone()));
    o.insert("remediation".into(), Json::Str(v.remediation.clone()));
    Json::Obj(o)
}

/// A declarative policy.
#[derive(Debug, Clone)]
pub struct Policy {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub control: String,
    pub action: String,
    pub match_kinds: Vec<String>,
    pub rules: Vec<(String, Json)>,
}

impl Policy {
    fn applies_to(&self, kind: &str) -> bool {
        if self.match_kinds.is_empty() {
            podspec_path(kind).is_some()
        } else {
            self.match_kinds.iter().any(|k| k == kind)
        }
    }
}

fn dig<'a>(obj: &'a Json, dotted: &str) -> Option<&'a Json> {
    let mut cur = obj;
    for part in dotted.split('.') {
        if part.is_empty() {
            continue;
        }
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn object_kind(o: &Json) -> String {
    o.get("kind").and_then(|k| k.as_str()).unwrap_or("").to_string()
}
fn object_name(o: &Json) -> String {
    o.get("metadata")
        .and_then(|m| m.get("name").or_else(|| m.get("generateName")))
        .and_then(|n| n.as_str())
        .unwrap_or("<unnamed>")
        .to_string()
}
fn object_namespace(o: &Json) -> String {
    o.get("metadata")
        .and_then(|m| m.get("namespace"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string()
}

struct ContainerRef<'a> {
    c: &'a Json,
    group: &'static str,
    idx: usize,
}

fn all_containers(ps: &Json) -> Vec<ContainerRef> {
    let mut out = Vec::new();
    for group in ["initContainers", "containers", "ephemeralContainers"] {
        if let Some(Json::Arr(list)) = ps.get(group) {
            for (idx, c) in list.iter().enumerate() {
                if matches!(c, Json::Obj(_)) {
                    out.push(ContainerRef { c, group, idx });
                }
            }
        }
    }
    out
}

fn container_name(cr: &ContainerRef) -> String {
    cr.c.get("name").and_then(|n| n.as_str()).map(String::from).unwrap_or(format!("#{}", cr.idx))
}

/// Split an image reference into (repo, tag). Digest pins count as a tag.
pub fn split_image(image: &str) -> (String, String) {
    if let Some(at) = image.find('@') {
        return (image[..at].to_string(), image[at + 1..].to_string());
    }
    let last_slash = image.rfind('/').map(|i| i as isize).unwrap_or(-1);
    let tail = &image[(last_slash + 1) as usize..];
    if let Some(colon) = tail.rfind(':') {
        let repo = format!("{}{}", &image[..(last_slash + 1) as usize], &tail[..colon]);
        return (repo, tail[colon + 1..].to_string());
    }
    (image.to_string(), String::new())
}

fn mk(p: &Policy, message: String, location: String, remediation: String) -> Violation {
    Violation {
        policy_id: p.id.clone(),
        severity: p.severity.clone(),
        title: p.title.clone(),
        control: p.control.clone(),
        message,
        action: p.action.clone(),
        location,
        remediation,
    }
}

fn spec_str(spec: &Json, key: &str) -> String {
    spec.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}
fn spec_str_list(spec: &Json, key: &str) -> Vec<String> {
    spec.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .map(|x| match x {
                    Json::Str(s) => s.clone(),
                    other => json::to_pretty(other),
                })
                .collect()
        })
        .unwrap_or_default()
}
fn fallback(spec: &Json, key: &str, def: &str) -> String {
    let s = spec_str(spec, key);
    if s.is_empty() { def.to_string() } else { s }
}

fn eval_rule(p: &Policy, verb: &str, spec: &Json, ps: &Json, ptr: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    match verb {
        "forbid_field" => {
            let path = spec_str(spec, "path");
            let want = spec.get("equals");
            for cr in all_containers(ps) {
                if let Some(val) = dig(cr.c, &path) {
                    if want.is_none() || want == Some(val) {
                        let suffix = if let Some(w) = want { format!("={}", json::to_pretty(w)) } else { String::new() };
                        out.push(mk(p,
                            format!("container '{}' sets {}{} which is forbidden.", container_name(&cr), path, suffix),
                            format!("{}/{}/{}/{}", ptr, cr.group, cr.idx, path.replace('.', "/")),
                            fallback(spec, "remediation", &format!("Remove or unset {}.", path))));
                    }
                }
            }
        }
        "require_field" => {
            let path = spec_str(spec, "path");
            let want = spec.get("equals");
            for cr in all_containers(ps) {
                let val = dig(cr.c, &path);
                let missing = val.is_none() || (want.is_some() && want != val);
                if missing {
                    out.push(mk(p,
                        format!("container '{}' must set {}.", container_name(&cr), path),
                        format!("{}/{}/{}/{}", ptr, cr.group, cr.idx, path.replace('.', "/")),
                        fallback(spec, "remediation", &format!("Set {}.", path))));
                }
            }
        }
        "forbid_pod_field" => {
            let path = spec_str(spec, "path");
            let want = spec.get("equals");
            if let Some(val) = dig(ps, &path) {
                if want.is_none() || want == Some(val) {
                    out.push(mk(p,
                        format!("pod sets {} which is forbidden.", path),
                        format!("{}/{}", ptr, path.replace('.', "/")),
                        fallback(spec, "remediation", &format!("Remove or unset pod field {}.", path))));
                }
            }
        }
        "require_pod_field" => {
            let path = spec_str(spec, "path");
            let want = spec.get("equals");
            let val = dig(ps, &path);
            if val.is_none() || (want.is_some() && want != val) {
                out.push(mk(p,
                    format!("pod must set {}.", path),
                    format!("{}/{}", ptr, path.replace('.', "/")),
                    fallback(spec, "remediation", &format!("Set pod field {}.", path))));
            }
        }
        "forbid_image_tag" => {
            let bad: Vec<String> = spec_str_list(spec, "tags").iter().map(|t| t.to_lowercase()).collect();
            let flag_untagged = spec.get("untagged").and_then(|u| u.as_bool()).unwrap_or(true);
            for cr in all_containers(ps) {
                let image = match cr.c.get("image").and_then(|i| i.as_str()) {
                    Some(s) if !s.is_empty() => s,
                    _ => continue,
                };
                let (_, tag) = split_image(image);
                if tag.is_empty() && flag_untagged {
                    out.push(mk(p,
                        format!("container '{}' image '{}' has no explicit tag (implicitly resolves to a mutable :latest).", container_name(&cr), image),
                        format!("{}/{}/{}/image", ptr, cr.group, cr.idx),
                        fallback(spec, "remediation", "Pin the image to an immutable tag or digest.")));
                } else if bad.contains(&tag.to_lowercase()) {
                    out.push(mk(p,
                        format!("container '{}' image '{}' uses forbidden tag ':{}'.", container_name(&cr), image, tag),
                        format!("{}/{}/{}/image", ptr, cr.group, cr.idx),
                        fallback(spec, "remediation", "Pin the image to an immutable tag or digest.")));
                }
            }
        }
        "require_registry" => {
            let allowed = spec_str_list(spec, "allowed");
            if allowed.is_empty() {
                return out;
            }
            for cr in all_containers(ps) {
                let image = cr.c.get("image").and_then(|i| i.as_str()).unwrap_or("");
                if image.is_empty() {
                    continue;
                }
                if !allowed.iter().any(|a| image.starts_with(a)) {
                    out.push(mk(p,
                        format!("container '{}' image '{}' is not from an allowed registry ({}).", container_name(&cr), image, allowed.join(", ")),
                        format!("{}/{}/{}/image", ptr, cr.group, cr.idx),
                        fallback(spec, "remediation", "Use an image from an approved registry.")));
                }
            }
        }
        "require_drop_caps" => {
            let mut need = spec_str_list(spec, "caps");
            if need.is_empty() {
                need = vec!["ALL".to_string()];
            }
            let need: Vec<String> = need.iter().map(|c| c.to_uppercase()).collect();
            for cr in all_containers(ps) {
                let dropped: Vec<String> = cr.c.get("securityContext")
                    .and_then(|sc| sc.get("capabilities"))
                    .and_then(|caps| caps.get("drop"))
                    .and_then(|d| d.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.to_uppercase()).collect())
                    .unwrap_or_default();
                if dropped.iter().any(|d| d == "ALL") {
                    continue;
                }
                let mut missing: Vec<String> = need.iter().filter(|n| !dropped.contains(n)).cloned().collect();
                missing.sort();
                if !missing.is_empty() {
                    let list = missing.iter().map(|m| format!("'{}'", m)).collect::<Vec<_>>().join(", ");
                    out.push(mk(p,
                        format!("container '{}' must drop capabilities [{}].", container_name(&cr), list),
                        format!("{}/{}/{}/securityContext/capabilities/drop", ptr, cr.group, cr.idx),
                        fallback(spec, "remediation", "Drop the required Linux capabilities.")));
                }
            }
        }
        "forbid_volume_type" => {
            let bad = spec_str_list(spec, "types");
            if let Some(Json::Arr(vols)) = ps.get("volumes") {
                for (idx, v) in vols.iter().enumerate() {
                    if let Json::Obj(map) = v {
                        for vt in &bad {
                            if map.contains_key(vt) {
                                let name = v.get("name").and_then(|n| n.as_str()).map(String::from).unwrap_or(format!("#{}", idx));
                                out.push(mk(p,
                                    format!("volume '{}' uses forbidden type '{}'.", name, vt),
                                    format!("{}/volumes/{}/{}", ptr, idx, vt),
                                    fallback(spec, "remediation", &format!("Do not mount {} volumes.", vt))));
                            }
                        }
                    }
                }
            }
        }
        "require_resource_limits" => {
            let mut needed = spec_str_list(spec, "resources");
            if needed.is_empty() {
                needed = vec!["cpu".to_string(), "memory".to_string()];
            }
            for cr in all_containers(ps) {
                if cr.group == "ephemeralContainers" {
                    continue;
                }
                let limits = cr.c.get("resources").and_then(|r| r.get("limits")).and_then(|l| l.as_object());
                let missing: Vec<&String> = needed.iter().filter(|r| limits.map(|l| !l.contains_key(*r)).unwrap_or(true)).collect();
                if !missing.is_empty() {
                    let list = missing.iter().map(|m| format!("'{}'", m)).collect::<Vec<_>>().join(", ");
                    out.push(mk(p,
                        format!("container '{}' is missing resource limits for [{}].", container_name(&cr), list),
                        format!("{}/{}/{}/resources/limits", ptr, cr.group, cr.idx),
                        fallback(spec, "remediation", "Set resources.limits.")));
                }
            }
        }
        _ => {}
    }
    out
}

/// Evaluate one Kubernetes object against the policies.
pub fn evaluate_object(obj: &Json, policies: &[Policy], source: &str) -> Decision {
    let kind = object_kind(obj);
    let mut decision = Decision {
        kind: kind.clone(),
        name: object_name(obj),
        namespace: object_namespace(obj),
        source: source.to_string(),
        violations: Vec::new(),
    };
    let path = match podspec_path(&kind) {
        Some(p) => p,
        None => return decision,
    };
    let ps = match dig(obj, path) {
        Some(p @ Json::Obj(_)) => p,
        _ => return decision,
    };
    let ptr = format!("/{}", path.replace('.', "/"));
    for p in policies {
        if !p.applies_to(&kind) || p.action == "mutate" {
            continue;
        }
        for (verb, spec) in &p.rules {
            decision.violations.extend(eval_rule(p, verb, spec, ps, &ptr));
        }
    }
    decision.violations.sort_by(|a, b| {
        severity_rank(&a.severity)
            .cmp(&severity_rank(&b.severity))
            .then(a.policy_id.cmp(&b.policy_id))
    });
    decision
}

fn unwrap_admission_review(o: Json) -> Json {
    if object_kind(&o) == "AdmissionReview" {
        if let Some(embedded) = o.get("request").and_then(|r| r.get("object")) {
            if matches!(embedded, Json::Obj(_)) {
                return embedded.clone();
            }
        }
    }
    o
}

/// Parse a JSON manifest / array / k8s List / AdmissionReview into objects.
pub fn parse_objects(text: &str) -> Result<Vec<Json>, String> {
    let root = json::parse(text)?;
    let objs: Vec<Json> = match root {
        Json::Arr(a) => a.into_iter().filter(|d| matches!(d, Json::Obj(_))).collect(),
        Json::Obj(ref map) if map.get("kind") == Some(&Json::Str("List".into())) => {
            match map.get("items") {
                Some(Json::Arr(items)) => items.iter().filter(|d| matches!(d, Json::Obj(_))).cloned().collect(),
                _ => vec![root.clone()],
            }
        }
        obj @ Json::Obj(_) => vec![obj],
        _ => vec![],
    };
    Ok(objs.into_iter().map(unwrap_admission_review).collect())
}

fn rule(verb: &str, kv: &[(&str, Json)]) -> (String, Json) {
    let mut m = BTreeMap::new();
    for (k, v) in kv {
        m.insert(k.to_string(), v.clone());
    }
    (verb.to_string(), Json::Obj(m))
}

fn strs(items: &[&str]) -> Json {
    Json::Arr(items.iter().map(|s| Json::Str(s.to_string())).collect())
}

fn policy(id: &str, title: &str, sev: &str, control: &str, rules: Vec<(String, Json)>) -> Policy {
    Policy {
        id: id.to_string(),
        title: title.to_string(),
        severity: sev.to_string(),
        control: control.to_string(),
        action: "deny".to_string(),
        match_kinds: vec![],
        rules,
    }
}

/// The bundled hardening policy library (original re-expression of public CIS /
/// NSA-CISA Kubernetes hardening guidance).
pub fn builtin_policies() -> Vec<Policy> {
    vec![
        policy("ADMITD-PRIV-001", "Deny privileged containers", "critical",
            "NSA-CISA K8s Hardening: least privilege / CIS 5.2.1",
            vec![rule("forbid_field", &[("path", Json::Str("securityContext.privileged".into())), ("equals", Json::Bool(true))])]),
        policy("ADMITD-PRIVESC-002", "Deny privilege escalation", "high",
            "NSA-CISA K8s Hardening: least privilege / CIS 5.2.5",
            vec![rule("forbid_field", &[("path", Json::Str("securityContext.allowPrivilegeEscalation".into())), ("equals", Json::Bool(true))])]),
        policy("ADMITD-HOSTNS-003", "Deny host namespaces (network / PID / IPC)", "high",
            "NSA-CISA K8s Hardening: pod isolation / CIS 5.2.2-5.2.4",
            vec![
                rule("forbid_pod_field", &[("path", Json::Str("hostNetwork".into())), ("equals", Json::Bool(true))]),
                rule("forbid_pod_field", &[("path", Json::Str("hostPID".into())), ("equals", Json::Bool(true))]),
                rule("forbid_pod_field", &[("path", Json::Str("hostIPC".into())), ("equals", Json::Bool(true))]),
            ]),
        policy("ADMITD-HOSTPATH-004", "Deny hostPath volumes", "high",
            "NSA-CISA K8s Hardening: volume isolation / CIS 5.2.x",
            vec![rule("forbid_volume_type", &[("types", strs(&["hostPath"]))])]),
        policy("ADMITD-NONROOT-005", "Require runAsNonRoot", "high",
            "NSA-CISA K8s Hardening: non-root containers / CIS 5.2.6",
            vec![rule("require_field", &[("path", Json::Str("securityContext.runAsNonRoot".into())), ("equals", Json::Bool(true))])]),
        policy("ADMITD-ROFS-006", "Require read-only root filesystem", "medium",
            "NSA-CISA K8s Hardening: immutable runtime / CIS 5.2.x",
            vec![rule("require_field", &[("path", Json::Str("securityContext.readOnlyRootFilesystem".into())), ("equals", Json::Bool(true))])]),
        policy("ADMITD-DROPCAPS-007", "Require dropping ALL Linux capabilities", "medium",
            "NSA-CISA K8s Hardening: capability reduction / CIS 5.2.7-5.2.9",
            vec![rule("require_drop_caps", &[("caps", strs(&["ALL"]))])]),
        policy("ADMITD-LATEST-008", "Deny :latest / untagged images", "medium",
            "Supply-chain integrity: immutable image references",
            vec![rule("forbid_image_tag", &[("tags", strs(&["latest"])), ("untagged", Json::Bool(true))])]),
        policy("ADMITD-LIMITS-009", "Require CPU and memory limits", "low",
            "Resource governance / DoS resistance / CIS 5.x",
            vec![rule("require_resource_limits", &[("resources", strs(&["cpu", "memory"]))])]),
        policy("ADMITD-SECCOMP-010", "Require a seccomp profile (RuntimeDefault or Localhost)", "medium",
            "NSA-CISA K8s Hardening: syscall reduction",
            vec![rule("require_field", &[("path", Json::Str("securityContext.seccompProfile.type".into())), ("equals", Json::Str("RuntimeDefault".into()))])]),
    ]
}

/// Evaluate every object in a manifest string, returning the aggregate report.
pub fn evaluate_text(text: &str, source: &str) -> Result<Json, String> {
    let policies = builtin_policies();
    let objs = parse_objects(text)?;
    let decisions: Vec<Decision> = objs.iter().map(|o| evaluate_object(o, &policies, source)).collect();
    let denied = decisions.iter().filter(|d| !d.allowed()).count();
    let total: usize = decisions.iter().map(|d| d.violations.len()).sum();
    let all_allowed = decisions.iter().all(|d| d.allowed());
    let mut obj = BTreeMap::new();
    obj.insert("tool".into(), Json::Str(TOOL_NAME.into()));
    obj.insert("version".into(), Json::Str(TOOL_VERSION.into()));
    obj.insert("objects_evaluated".into(), Json::Num(decisions.len() as f64));
    obj.insert("objects_denied".into(), Json::Num(denied as f64));
    obj.insert("total_violations".into(), Json::Num(total as f64));
    obj.insert("allowed".into(), Json::Bool(all_allowed));
    obj.insert("decisions".into(), Json::Arr(decisions.iter().map(|d| d.to_json()).collect()));
    Ok(Json::Obj(obj))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(spec: &str) -> Json {
        json::parse(&format!(
            r#"{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"p","namespace":"default"}},"spec":{}}}"#,
            spec
        ))
        .unwrap()
    }
    fn ids(d: &Decision) -> Vec<String> {
        d.violations.iter().map(|v| v.policy_id.clone()).collect()
    }

    #[test]
    fn builtins_loaded() {
        assert!(builtin_policies().len() >= 10);
        assert!(builtin_policies().iter().any(|p| p.id == "ADMITD-PRIV-001"));
    }

    #[test]
    fn privileged_denied() {
        let obj = pod(r#"{"containers":[{"name":"c","image":"x:1.0","securityContext":{"privileged":true}}]}"#);
        let d = evaluate_object(&obj, &builtin_policies(), "");
        assert!(!d.allowed());
        assert!(ids(&d).contains(&"ADMITD-PRIV-001".to_string()));
    }

    #[test]
    fn host_namespaces_denied() {
        let obj = pod(r#"{"hostNetwork":true,"hostPID":true,"containers":[{"name":"c","image":"x:1.0"}]}"#);
        assert!(ids(&evaluate_object(&obj, &builtin_policies(), "")).contains(&"ADMITD-HOSTNS-003".to_string()));
    }

    #[test]
    fn hostpath_denied() {
        let obj = pod(r#"{"volumes":[{"name":"h","hostPath":{"path":"/"}}],"containers":[{"name":"c","image":"x:1.0"}]}"#);
        assert!(ids(&evaluate_object(&obj, &builtin_policies(), "")).contains(&"ADMITD-HOSTPATH-004".to_string()));
    }

    #[test]
    fn latest_tag_denied() {
        let obj = pod(r#"{"containers":[{"name":"c","image":"nginx:latest"}]}"#);
        assert!(ids(&evaluate_object(&obj, &builtin_policies(), "")).contains(&"ADMITD-LATEST-008".to_string()));
    }

    #[test]
    fn untagged_denied() {
        let obj = pod(r#"{"containers":[{"name":"c","image":"redis"}]}"#);
        assert!(ids(&evaluate_object(&obj, &builtin_policies(), "")).contains(&"ADMITD-LATEST-008".to_string()));
    }

    #[test]
    fn digest_pinned_ok() {
        let obj = pod(r#"{"containers":[{"name":"c","image":"registry.internal/a@sha256:abc"}]}"#);
        assert!(!ids(&evaluate_object(&obj, &builtin_policies(), "")).contains(&"ADMITD-LATEST-008".to_string()));
    }

    #[test]
    fn fully_hardened_allowed() {
        let obj = pod(r#"{"containers":[{"name":"c","image":"registry.internal/a:1.0","securityContext":{"privileged":false,"allowPrivilegeEscalation":false,"runAsNonRoot":true,"readOnlyRootFilesystem":true,"seccompProfile":{"type":"RuntimeDefault"},"capabilities":{"drop":["ALL"]}},"resources":{"limits":{"cpu":"100m","memory":"64Mi"}}}]}"#);
        let d = evaluate_object(&obj, &builtin_policies(), "");
        assert!(d.allowed());
        assert_eq!(d.violations.len(), 0);
    }

    #[test]
    fn non_workload_allowed() {
        let obj = json::parse(r#"{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm"}}"#).unwrap();
        assert!(evaluate_object(&obj, &builtin_policies(), "").allowed());
    }

    #[test]
    fn deployment_nested_located() {
        let obj = json::parse(r#"{"kind":"Deployment","metadata":{"name":"d"},"spec":{"template":{"spec":{"containers":[{"name":"c","image":"x:latest","securityContext":{"privileged":true}}]}}}}"#).unwrap();
        let d = evaluate_object(&obj, &builtin_policies(), "");
        assert!(!d.allowed());
        assert!(d.violations.iter().any(|v| v.location.starts_with("/spec/template/spec/containers/0")));
    }

    #[test]
    fn cronjob_deep_denied() {
        let obj = json::parse(r#"{"kind":"CronJob","metadata":{"name":"cj"},"spec":{"jobTemplate":{"spec":{"template":{"spec":{"containers":[{"name":"c","image":"x:latest"}]}}}}}}"#).unwrap();
        assert!(!evaluate_object(&obj, &builtin_policies(), "").allowed());
    }

    #[test]
    fn split_image_port_not_tag() {
        let (repo, tag) = split_image("registry.local:5000/team/app:1.2");
        assert_eq!(repo, "registry.local:5000/team/app");
        assert_eq!(tag, "1.2");
    }

    #[test]
    fn split_image_untagged() {
        assert_eq!(split_image("redis").1, "");
    }

    #[test]
    fn parse_admission_review_unwraps() {
        let objs = parse_objects(r#"{"kind":"AdmissionReview","request":{"uid":"u","object":{"kind":"Pod","metadata":{"name":"p"},"spec":{"containers":[]}}}}"#).unwrap();
        assert_eq!(objs.len(), 1);
        assert_eq!(object_kind(&objs[0]), "Pod");
    }

    #[test]
    fn parse_list_object() {
        let objs = parse_objects(r#"{"kind":"List","items":[{"kind":"Pod","metadata":{"name":"a"},"spec":{"containers":[]}},{"kind":"Pod","metadata":{"name":"b"},"spec":{"containers":[]}}]}"#).unwrap();
        assert_eq!(objs.len(), 2);
    }

    #[test]
    fn require_registry_custom() {
        let pol = Policy {
            id: "ADMITD-REG-1".into(), title: "registry".into(), severity: "high".into(),
            control: "".into(), action: "deny".into(), match_kinds: vec![],
            rules: vec![rule("require_registry", &[("allowed", strs(&["registry.internal/"]))])],
        };
        let obj = pod(r#"{"containers":[{"name":"c","image":"docker.io/redis:7"}]}"#);
        let d = evaluate_object(&obj, &[pol], "");
        assert!(!d.allowed());
        assert_eq!(d.violations[0].policy_id, "ADMITD-REG-1");
    }

    #[test]
    fn evaluate_text_report() {
        let report = evaluate_text(r#"{"kind":"Pod","metadata":{"name":"p"},"spec":{"containers":[{"name":"c","image":"x:latest","securityContext":{"privileged":true}}]}}"#, "<inline>").unwrap();
        assert_eq!(report.get("allowed"), Some(&Json::Bool(false)));
    }

    #[test]
    fn json_roundtrip_pretty() {
        let v = json::parse(r#"{"a":[1,2,true,null],"b":"x"}"#).unwrap();
        let s = json::to_pretty(&v);
        let v2 = json::parse(&s).unwrap();
        assert_eq!(v, v2);
    }
}
