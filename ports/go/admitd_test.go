package main

import "testing"

func ids(d Decision) map[string]bool {
	m := map[string]bool{}
	for _, v := range d.Violations {
		m[v.PolicyID] = true
	}
	return m
}

func pod(spec map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]interface{}{"name": "p", "namespace": "default"},
		"spec":     spec,
	}
}

func TestBuiltinsLoaded(t *testing.T) {
	pols := BuiltinPolicies()
	if len(pols) < 10 {
		t.Fatalf("expected >=10 builtin policies, got %d", len(pols))
	}
}

func TestPrivilegedDenied(t *testing.T) {
	obj := pod(map[string]interface{}{"containers": []interface{}{
		map[string]interface{}{"name": "c", "image": "x:1.0",
			"securityContext": map[string]interface{}{"privileged": true}},
	}})
	d := EvaluateObject(obj, BuiltinPolicies(), "")
	if d.Allowed() {
		t.Fatal("privileged pod should be denied")
	}
	if !ids(d)["ADMITD-PRIV-001"] {
		t.Fatal("expected ADMITD-PRIV-001")
	}
}

func TestHostNamespacesDenied(t *testing.T) {
	obj := pod(map[string]interface{}{"hostNetwork": true, "hostPID": true,
		"containers": []interface{}{map[string]interface{}{"name": "c", "image": "x:1.0"}}})
	if !ids(EvaluateObject(obj, BuiltinPolicies(), ""))["ADMITD-HOSTNS-003"] {
		t.Fatal("expected ADMITD-HOSTNS-003")
	}
}

func TestHostPathDenied(t *testing.T) {
	obj := pod(map[string]interface{}{
		"volumes":    []interface{}{map[string]interface{}{"name": "h", "hostPath": map[string]interface{}{"path": "/"}}},
		"containers": []interface{}{map[string]interface{}{"name": "c", "image": "x:1.0"}}})
	if !ids(EvaluateObject(obj, BuiltinPolicies(), ""))["ADMITD-HOSTPATH-004"] {
		t.Fatal("expected ADMITD-HOSTPATH-004")
	}
}

func TestLatestTagDenied(t *testing.T) {
	obj := pod(map[string]interface{}{"containers": []interface{}{
		map[string]interface{}{"name": "c", "image": "nginx:latest"}}})
	if !ids(EvaluateObject(obj, BuiltinPolicies(), ""))["ADMITD-LATEST-008"] {
		t.Fatal("expected ADMITD-LATEST-008 for :latest")
	}
}

func TestUntaggedDenied(t *testing.T) {
	obj := pod(map[string]interface{}{"containers": []interface{}{
		map[string]interface{}{"name": "c", "image": "redis"}}})
	if !ids(EvaluateObject(obj, BuiltinPolicies(), ""))["ADMITD-LATEST-008"] {
		t.Fatal("expected ADMITD-LATEST-008 for untagged")
	}
}

func TestDigestPinnedOk(t *testing.T) {
	obj := pod(map[string]interface{}{"containers": []interface{}{
		map[string]interface{}{"name": "c", "image": "registry.internal/a@sha256:abc"}}})
	if ids(EvaluateObject(obj, BuiltinPolicies(), ""))["ADMITD-LATEST-008"] {
		t.Fatal("digest-pinned image should not fire ADMITD-LATEST-008")
	}
}

func TestFullyHardenedAllowed(t *testing.T) {
	obj := pod(map[string]interface{}{"containers": []interface{}{
		map[string]interface{}{"name": "c", "image": "registry.internal/a:1.0",
			"securityContext": map[string]interface{}{
				"privileged": false, "allowPrivilegeEscalation": false,
				"runAsNonRoot": true, "readOnlyRootFilesystem": true,
				"seccompProfile": map[string]interface{}{"type": "RuntimeDefault"},
				"capabilities":   map[string]interface{}{"drop": []interface{}{"ALL"}},
			},
			"resources": map[string]interface{}{"limits": map[string]interface{}{"cpu": "100m", "memory": "64Mi"}}},
	}})
	d := EvaluateObject(obj, BuiltinPolicies(), "")
	if !d.Allowed() {
		t.Fatalf("hardened pod should be allowed, got %d violations", len(d.Violations))
	}
	if len(d.Violations) != 0 {
		t.Fatalf("expected 0 violations, got %d", len(d.Violations))
	}
}

func TestNonWorkloadAllowed(t *testing.T) {
	obj := map[string]interface{}{"apiVersion": "v1", "kind": "ConfigMap",
		"metadata": map[string]interface{}{"name": "cm"}}
	if !EvaluateObject(obj, BuiltinPolicies(), "").Allowed() {
		t.Fatal("ConfigMap should be allowed")
	}
}

func TestDeploymentNestedPodSpec(t *testing.T) {
	obj := map[string]interface{}{"kind": "Deployment", "metadata": map[string]interface{}{"name": "d"},
		"spec": map[string]interface{}{"template": map[string]interface{}{"spec": map[string]interface{}{
			"containers": []interface{}{map[string]interface{}{"name": "c", "image": "x:latest",
				"securityContext": map[string]interface{}{"privileged": true}}}}}}}
	d := EvaluateObject(obj, BuiltinPolicies(), "")
	if d.Allowed() {
		t.Fatal("privileged deployment should be denied")
	}
	found := false
	for _, v := range d.Violations {
		if len(v.Location) >= 26 && v.Location[:26] == "/spec/template/spec/contai" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a violation located in nested podspec")
	}
}

func TestSplitImage(t *testing.T) {
	if repo, tag := splitImage("registry.local:5000/team/app:1.2"); repo != "registry.local:5000/team/app" || tag != "1.2" {
		t.Fatalf("port not tag: got repo=%q tag=%q", repo, tag)
	}
	if _, tag := splitImage("redis"); tag != "" {
		t.Fatalf("untagged should have empty tag, got %q", tag)
	}
}

func TestParseAdmissionReview(t *testing.T) {
	data := []byte(`{"kind":"AdmissionReview","request":{"uid":"u","object":{"kind":"Pod","metadata":{"name":"p"},"spec":{"containers":[{"name":"c","image":"x:latest","securityContext":{"privileged":true}}]}}}}`)
	objs, err := parseObjects(data)
	if err != nil || len(objs) != 1 {
		t.Fatalf("parse failed: %v", err)
	}
	if objectKind(objs[0]) != "Pod" {
		t.Fatalf("expected unwrapped Pod, got %s", objectKind(objs[0]))
	}
}

func TestListObject(t *testing.T) {
	data := []byte(`{"kind":"List","items":[{"kind":"Pod","metadata":{"name":"a"},"spec":{"containers":[]}},{"kind":"Pod","metadata":{"name":"b"},"spec":{"containers":[]}}]}`)
	objs, err := parseObjects(data)
	if err != nil || len(objs) != 2 {
		t.Fatalf("expected 2 objects from List, got %d (%v)", len(objs), err)
	}
}
