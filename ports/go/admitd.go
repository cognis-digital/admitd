// Command admitd is a Go port of the admitd Kubernetes policy-as-code
// admission engine. It mirrors the core surface of the primary Python CLI:
// it loads the built-in CIS / NSA-CISA hardening policy library, evaluates a
// Kubernetes object (or an AdmissionReview wrapping one) read from a file or
// stdin, and prints an allow/deny decision as JSON.
//
// This port is intentionally dependency-free (standard library only),
// deterministic, and offline — it performs no network access of any kind.
//
//	go run ./ports/go eval manifest.json          # evaluate, print JSON
//	go run ./ports/go policies                     # list built-in policies
//	cat manifest.json | go run ./ports/go eval -   # read from stdin
//
// Usage as a package mirrors the Python core: BuiltinPolicies(),
// EvaluateObject(obj, policies), and the Decision type.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// ToolName / ToolVersion mirror the Python package identity.
const (
	ToolName    = "admitd"
	ToolVersion = "0.1.0"
)

// severityOrder ranks severities (lower = more severe) for sorting + gating.
var severityOrder = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

// workloadPodSpecPath maps a container-bearing kind to the dotted path of its
// PodSpec, matching the Python engine exactly.
var workloadPodSpecPath = map[string]string{
	"Pod":                   "spec",
	"Deployment":            "spec.template.spec",
	"ReplicaSet":            "spec.template.spec",
	"StatefulSet":           "spec.template.spec",
	"DaemonSet":             "spec.template.spec",
	"Job":                   "spec.template.spec",
	"CronJob":               "spec.jobTemplate.spec.template.spec",
	"ReplicationController": "spec.template.spec",
}

// Rule is a single verb keyed map, e.g. {"forbid_field": {...}}.
type Rule map[string]map[string]interface{}

// Policy is a declarative allow/deny/mutate policy.
type Policy struct {
	ID         string
	Title      string
	Severity   string
	Control    string
	Action     string // deny | warn | mutate
	MatchKinds []string
	Rules      []Rule
}

func (p Policy) appliesTo(kind string) bool {
	if len(p.MatchKinds) == 0 {
		_, ok := workloadPodSpecPath[kind]
		return ok
	}
	for _, k := range p.MatchKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Violation is a failed (or warned) policy rule against one object.
type Violation struct {
	PolicyID    string `json:"policy_id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Control     string `json:"control"`
	Message     string `json:"message"`
	Action      string `json:"action"`
	Location    string `json:"location"`
	Remediation string `json:"remediation"`
}

// Decision is the verdict for one object.
type Decision struct {
	Kind       string      `json:"kind"`
	Name       string      `json:"name"`
	Namespace  string      `json:"namespace"`
	Source     string      `json:"source"`
	Violations []Violation `json:"violations"`
}

// DenyViolations returns the deny-action violations.
func (d Decision) DenyViolations() []Violation {
	out := []Violation{}
	for _, v := range d.Violations {
		if v.Action == "deny" {
			out = append(out, v)
		}
	}
	return out
}

// Allowed reports whether the object is admitted (no deny-action violations).
func (d Decision) Allowed() bool { return len(d.DenyViolations()) == 0 }

func (d Decision) counts() map[string]int {
	c := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, v := range d.Violations {
		c[v.Severity]++
	}
	return c
}

// MarshalJSON renders a decision in the same shape as the Python to_dict().
func (d Decision) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"kind":       d.Kind,
		"name":       d.Name,
		"namespace":  d.Namespace,
		"source":     d.Source,
		"allowed":    d.Allowed(),
		"counts":     d.counts(),
		"violations": d.Violations,
		"patches":    []interface{}{},
	})
}

// ---- object navigation ----------------------------------------------------

func dig(obj interface{}, dotted string) (interface{}, bool) {
	cur := obj
	for _, part := range strings.Split(dotted, ".") {
		if part == "" {
			continue
		}
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func asMap(v interface{}) map[string]interface{} {
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return nil
}

func objectKind(o map[string]interface{}) string {
	if s, ok := o["kind"].(string); ok {
		return s
	}
	return ""
}

func objectName(o map[string]interface{}) string {
	meta := asMap(o["metadata"])
	if meta != nil {
		if s, ok := meta["name"].(string); ok {
			return s
		}
		if s, ok := meta["generateName"].(string); ok {
			return s
		}
	}
	return "<unnamed>"
}

func objectNamespace(o map[string]interface{}) string {
	meta := asMap(o["metadata"])
	if meta != nil {
		if s, ok := meta["namespace"].(string); ok {
			return s
		}
	}
	return ""
}

func podSpec(o map[string]interface{}) (map[string]interface{}, string) {
	path, ok := workloadPodSpecPath[objectKind(o)]
	if !ok {
		return nil, ""
	}
	spec, found := dig(o, path)
	if !found {
		return nil, ""
	}
	m := asMap(spec)
	if m == nil {
		return nil, ""
	}
	return m, "/" + strings.ReplaceAll(path, ".", "/")
}

type containerRef struct {
	c     map[string]interface{}
	group string
	idx   int
}

func allContainers(ps map[string]interface{}) []containerRef {
	out := []containerRef{}
	for _, group := range []string{"initContainers", "containers", "ephemeralContainers"} {
		list, _ := ps[group].([]interface{})
		for i, raw := range list {
			if m := asMap(raw); m != nil {
				out = append(out, containerRef{m, group, i})
			}
		}
	}
	return out
}

func containerField(c map[string]interface{}, path string) (interface{}, bool) {
	var cur interface{} = c
	for _, part := range strings.Split(path, ".") {
		m := asMap(cur)
		if m == nil {
			return nil, false
		}
		v, ok := m[part]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func containerName(c containerRef) string {
	if s, ok := c.c["name"].(string); ok {
		return s
	}
	return fmt.Sprintf("#%d", c.idx)
}

// ---- rule evaluation ------------------------------------------------------

func mk(p Policy, msg, loc, rem string) Violation {
	return Violation{p.ID, p.Severity, p.Title, p.Control, msg, p.Action, loc, rem}
}

func specString(spec map[string]interface{}, key string) string {
	if s, ok := spec[key].(string); ok {
		return s
	}
	return ""
}

func specStringList(spec map[string]interface{}, key string) []string {
	out := []string{}
	if list, ok := spec[key].([]interface{}); ok {
		for _, v := range list {
			out = append(out, fmt.Sprint(v))
		}
	}
	return out
}

func jsonEq(a, b interface{}) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func evalRule(p Policy, verb string, spec map[string]interface{}, ps map[string]interface{}, pointer string) []Violation {
	out := []Violation{}
	switch verb {
	case "forbid_field":
		path := specString(spec, "path")
		want, hasWant := spec["equals"]
		for _, cr := range allContainers(ps) {
			val, present := containerField(cr.c, path)
			if present && (!hasWant || jsonEq(val, want)) {
				suffix := ""
				if hasWant {
					b, _ := json.Marshal(val)
					suffix = "=" + string(b)
				}
				out = append(out, mk(p,
					fmt.Sprintf("container '%s' sets %s%s which is forbidden.", containerName(cr), path, suffix),
					fmt.Sprintf("%s/%s/%d/%s", pointer, cr.group, cr.idx, strings.ReplaceAll(path, ".", "/")),
					fallback(spec, "remediation", "Remove or unset "+path+".")))
			}
		}
	case "require_field":
		path := specString(spec, "path")
		want, hasWant := spec["equals"]
		for _, cr := range allContainers(ps) {
			val, present := containerField(cr.c, path)
			if !present || (hasWant && !jsonEq(val, want)) {
				out = append(out, mk(p,
					fmt.Sprintf("container '%s' must set %s.", containerName(cr), path),
					fmt.Sprintf("%s/%s/%d/%s", pointer, cr.group, cr.idx, strings.ReplaceAll(path, ".", "/")),
					fallback(spec, "remediation", "Set "+path+".")))
			}
		}
	case "forbid_pod_field":
		path := specString(spec, "path")
		want, hasWant := spec["equals"]
		if val, present := containerField(ps, path); present && (!hasWant || jsonEq(val, want)) {
			out = append(out, mk(p,
				fmt.Sprintf("pod sets %s which is forbidden.", path),
				fmt.Sprintf("%s/%s", pointer, strings.ReplaceAll(path, ".", "/")),
				fallback(spec, "remediation", "Remove or unset pod field "+path+".")))
		}
	case "require_pod_field":
		path := specString(spec, "path")
		want, hasWant := spec["equals"]
		val, present := containerField(ps, path)
		if !present || (hasWant && !jsonEq(val, want)) {
			out = append(out, mk(p,
				fmt.Sprintf("pod must set %s.", path),
				fmt.Sprintf("%s/%s", pointer, strings.ReplaceAll(path, ".", "/")),
				fallback(spec, "remediation", "Set pod field "+path+".")))
		}
	case "forbid_image_tag":
		bad := map[string]bool{}
		for _, t := range specStringList(spec, "tags") {
			bad[strings.ToLower(t)] = true
		}
		flagUntagged := true
		if u, ok := spec["untagged"].(bool); ok {
			flagUntagged = u
		}
		for _, cr := range allContainers(ps) {
			image, _ := cr.c["image"].(string)
			if image == "" {
				continue
			}
			_, tag := splitImage(image)
			if tag == "" && flagUntagged {
				out = append(out, mk(p,
					fmt.Sprintf("container '%s' image '%s' has no explicit tag (implicitly resolves to a mutable :latest).", containerName(cr), image),
					fmt.Sprintf("%s/%s/%d/image", pointer, cr.group, cr.idx),
					fallback(spec, "remediation", "Pin the image to an immutable tag or digest.")))
			} else if bad[strings.ToLower(tag)] {
				out = append(out, mk(p,
					fmt.Sprintf("container '%s' image '%s' uses forbidden tag ':%s'.", containerName(cr), image, tag),
					fmt.Sprintf("%s/%s/%d/image", pointer, cr.group, cr.idx),
					fallback(spec, "remediation", "Pin the image to an immutable tag or digest.")))
			}
		}
	case "require_registry":
		allowed := specStringList(spec, "allowed")
		if len(allowed) == 0 {
			return out
		}
		for _, cr := range allContainers(ps) {
			image, _ := cr.c["image"].(string)
			if image == "" {
				continue
			}
			ok := false
			for _, a := range allowed {
				if strings.HasPrefix(image, a) {
					ok = true
					break
				}
			}
			if !ok {
				out = append(out, mk(p,
					fmt.Sprintf("container '%s' image '%s' is not from an allowed registry (%s).", containerName(cr), image, strings.Join(allowed, ", ")),
					fmt.Sprintf("%s/%s/%d/image", pointer, cr.group, cr.idx),
					fallback(spec, "remediation", "Use an image from an approved registry.")))
			}
		}
	case "require_drop_caps":
		need := specStringList(spec, "caps")
		if len(need) == 0 {
			need = []string{"ALL"}
		}
		for _, cr := range allContainers(ps) {
			sc := asMap(cr.c["securityContext"])
			dropped := map[string]bool{}
			if sc != nil {
				if caps := asMap(sc["capabilities"]); caps != nil {
					if list, ok := caps["drop"].([]interface{}); ok {
						for _, d := range list {
							dropped[strings.ToUpper(fmt.Sprint(d))] = true
						}
					}
				}
			}
			if dropped["ALL"] {
				continue
			}
			missing := []string{}
			for _, n := range need {
				if !dropped[strings.ToUpper(n)] {
					missing = append(missing, strings.ToUpper(n))
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				out = append(out, mk(p,
					fmt.Sprintf("container '%s' must drop capabilities %v.", containerName(cr), missing),
					fmt.Sprintf("%s/%s/%d/securityContext/capabilities/drop", pointer, cr.group, cr.idx),
					fallback(spec, "remediation", "Drop the required Linux capabilities.")))
			}
		}
	case "forbid_volume_type":
		bad := specStringList(spec, "types")
		vols, _ := ps["volumes"].([]interface{})
		for i, raw := range vols {
			v := asMap(raw)
			if v == nil {
				continue
			}
			for _, vt := range bad {
				if _, has := v[vt]; has {
					name := fmt.Sprintf("#%d", i)
					if n, ok := v["name"].(string); ok {
						name = n
					}
					out = append(out, mk(p,
						fmt.Sprintf("volume '%s' uses forbidden type '%s'.", name, vt),
						fmt.Sprintf("%s/volumes/%d/%s", pointer, i, vt),
						fallback(spec, "remediation", "Do not mount "+vt+" volumes.")))
				}
			}
		}
	case "require_resource_limits":
		needed := specStringList(spec, "resources")
		if len(needed) == 0 {
			needed = []string{"cpu", "memory"}
		}
		for _, cr := range allContainers(ps) {
			if cr.group == "ephemeralContainers" {
				continue
			}
			limits := map[string]interface{}{}
			if res := asMap(cr.c["resources"]); res != nil {
				if l := asMap(res["limits"]); l != nil {
					limits = l
				}
			}
			missing := []string{}
			for _, r := range needed {
				if _, ok := limits[r]; !ok {
					missing = append(missing, r)
				}
			}
			if len(missing) > 0 {
				out = append(out, mk(p,
					fmt.Sprintf("container '%s' is missing resource limits for %v.", containerName(cr), missing),
					fmt.Sprintf("%s/%s/%d/resources/limits", pointer, cr.group, cr.idx),
					fallback(spec, "remediation", "Set resources.limits.")))
			}
		}
	}
	return out
}

func fallback(spec map[string]interface{}, key, def string) string {
	if s, ok := spec[key].(string); ok && s != "" {
		return s
	}
	return def
}

func splitImage(image string) (repo, tag string) {
	if i := strings.Index(image, "@"); i >= 0 {
		return image[:i], image[i+1:]
	}
	lastSlash := strings.LastIndex(image, "/")
	tail := image[lastSlash+1:]
	if i := strings.LastIndex(tail, ":"); i >= 0 {
		return image[:lastSlash+1] + tail[:i], tail[i+1:]
	}
	return image, ""
}

// EvaluateObject evaluates one object against the policies.
func EvaluateObject(obj map[string]interface{}, policies []Policy, source string) Decision {
	d := Decision{
		Kind:       objectKind(obj),
		Name:       objectName(obj),
		Namespace:  objectNamespace(obj),
		Source:     source,
		Violations: []Violation{},
	}
	ps, pointer := podSpec(obj)
	if ps == nil {
		return d
	}
	for _, p := range policies {
		if !p.appliesTo(d.Kind) || p.Action == "mutate" {
			continue
		}
		for _, rule := range p.Rules {
			for verb, spec := range rule {
				d.Violations = append(d.Violations, evalRule(p, verb, spec, ps, pointer)...)
			}
		}
	}
	sort.SliceStable(d.Violations, func(i, j int) bool {
		si, sj := severityOrder[d.Violations[i].Severity], severityOrder[d.Violations[j].Severity]
		if si != sj {
			return si < sj
		}
		return d.Violations[i].PolicyID < d.Violations[j].PolicyID
	})
	return d
}

// ---- AdmissionReview unwrap + manifest loading ----------------------------

func unwrapAdmissionReview(o map[string]interface{}) map[string]interface{} {
	if objectKind(o) == "AdmissionReview" {
		if req := asMap(o["request"]); req != nil {
			if embedded := asMap(req["object"]); embedded != nil {
				return embedded
			}
		}
	}
	return o
}

func parseObjects(data []byte) ([]map[string]interface{}, error) {
	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	objs := []map[string]interface{}{}
	switch v := root.(type) {
	case []interface{}:
		for _, raw := range v {
			if m := asMap(raw); m != nil {
				objs = append(objs, m)
			}
		}
	case map[string]interface{}:
		if v["kind"] == "List" {
			if items, ok := v["items"].([]interface{}); ok {
				for _, raw := range items {
					if m := asMap(raw); m != nil {
						objs = append(objs, m)
					}
				}
				break
			}
		}
		objs = append(objs, v)
	}
	out := []map[string]interface{}{}
	for _, o := range objs {
		out = append(out, unwrapAdmissionReview(o))
	}
	return out, nil
}

// ---- built-in policy library ----------------------------------------------

func r(verb string, kv map[string]interface{}) Rule { return Rule{verb: kv} }

// BuiltinPolicies returns the bundled hardening policy library (original
// re-expression of public CIS / NSA-CISA Kubernetes hardening guidance).
func BuiltinPolicies() []Policy {
	return []Policy{
		{ID: "ADMITD-PRIV-001", Title: "Deny privileged containers", Severity: "critical",
			Control: "NSA-CISA K8s Hardening: least privilege / CIS 5.2.1", Action: "deny",
			Rules: []Rule{r("forbid_field", map[string]interface{}{"path": "securityContext.privileged", "equals": true})}},
		{ID: "ADMITD-PRIVESC-002", Title: "Deny privilege escalation", Severity: "high",
			Control: "NSA-CISA K8s Hardening: least privilege / CIS 5.2.5", Action: "deny",
			Rules: []Rule{r("forbid_field", map[string]interface{}{"path": "securityContext.allowPrivilegeEscalation", "equals": true})}},
		{ID: "ADMITD-HOSTNS-003", Title: "Deny host namespaces (network / PID / IPC)", Severity: "high",
			Control: "NSA-CISA K8s Hardening: pod isolation / CIS 5.2.2-5.2.4", Action: "deny",
			Rules: []Rule{
				r("forbid_pod_field", map[string]interface{}{"path": "hostNetwork", "equals": true}),
				r("forbid_pod_field", map[string]interface{}{"path": "hostPID", "equals": true}),
				r("forbid_pod_field", map[string]interface{}{"path": "hostIPC", "equals": true}),
			}},
		{ID: "ADMITD-HOSTPATH-004", Title: "Deny hostPath volumes", Severity: "high",
			Control: "NSA-CISA K8s Hardening: volume isolation / CIS 5.2.x", Action: "deny",
			Rules: []Rule{r("forbid_volume_type", map[string]interface{}{"types": []interface{}{"hostPath"}})}},
		{ID: "ADMITD-NONROOT-005", Title: "Require runAsNonRoot", Severity: "high",
			Control: "NSA-CISA K8s Hardening: non-root containers / CIS 5.2.6", Action: "deny",
			Rules: []Rule{r("require_field", map[string]interface{}{"path": "securityContext.runAsNonRoot", "equals": true})}},
		{ID: "ADMITD-ROFS-006", Title: "Require read-only root filesystem", Severity: "medium",
			Control: "NSA-CISA K8s Hardening: immutable runtime / CIS 5.2.x", Action: "deny",
			Rules: []Rule{r("require_field", map[string]interface{}{"path": "securityContext.readOnlyRootFilesystem", "equals": true})}},
		{ID: "ADMITD-DROPCAPS-007", Title: "Require dropping ALL Linux capabilities", Severity: "medium",
			Control: "NSA-CISA K8s Hardening: capability reduction / CIS 5.2.7-5.2.9", Action: "deny",
			Rules: []Rule{r("require_drop_caps", map[string]interface{}{"caps": []interface{}{"ALL"}})}},
		{ID: "ADMITD-LATEST-008", Title: "Deny :latest / untagged images", Severity: "medium",
			Control: "Supply-chain integrity: immutable image references", Action: "deny",
			Rules: []Rule{r("forbid_image_tag", map[string]interface{}{"tags": []interface{}{"latest"}, "untagged": true})}},
		{ID: "ADMITD-LIMITS-009", Title: "Require CPU and memory limits", Severity: "low",
			Control: "Resource governance / DoS resistance / CIS 5.x", Action: "deny",
			Rules: []Rule{r("require_resource_limits", map[string]interface{}{"resources": []interface{}{"cpu", "memory"}})}},
		{ID: "ADMITD-SECCOMP-010", Title: "Require a seccomp profile (RuntimeDefault or Localhost)", Severity: "medium",
			Control: "NSA-CISA K8s Hardening: syscall reduction", Action: "deny",
			Rules: []Rule{r("require_field", map[string]interface{}{"path": "securityContext.seccompProfile.type", "equals": "RuntimeDefault"})}},
	}
}

// ---- CLI ------------------------------------------------------------------

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func runEval(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: admitd eval <manifest|->")
		return 2
	}
	data, err := readInput(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	objs, err := parseObjects(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	policies := BuiltinPolicies()
	decisions := []Decision{}
	for _, o := range objs {
		decisions = append(decisions, EvaluateObject(o, policies, args[0]))
	}
	denied := 0
	total := 0
	allAllowed := true
	for _, d := range decisions {
		if !d.Allowed() {
			denied++
			allAllowed = false
		}
		total += len(d.Violations)
	}
	out := map[string]interface{}{
		"tool":              ToolName,
		"version":           ToolVersion,
		"objects_evaluated": len(decisions),
		"objects_denied":    denied,
		"total_violations":  total,
		"allowed":           allAllowed,
		"decisions":         decisions,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	if !allAllowed {
		return 1
	}
	return 0
}

func runPolicies() int {
	pols := BuiltinPolicies()
	rows := []map[string]interface{}{}
	for _, p := range pols {
		rows = append(rows, map[string]interface{}{
			"id": p.ID, "title": p.Title, "severity": p.Severity,
			"control": p.Control, "action": p.Action, "rule_count": len(p.Rules),
		})
	}
	b, _ := json.MarshalIndent(map[string]interface{}{
		"tool": ToolName, "version": ToolVersion, "count": len(pols), "policies": rows,
	}, "", "  ")
	fmt.Println(string(b))
	return 0
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: admitd <eval|policies|--version> [args]")
		os.Exit(2)
	}
	switch args[0] {
	case "--version":
		fmt.Printf("%s %s\n", ToolName, ToolVersion)
		os.Exit(0)
	case "eval":
		os.Exit(runEval(args[1:]))
	case "policies":
		os.Exit(runPolicies())
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", args[0])
		os.Exit(2)
	}
}
