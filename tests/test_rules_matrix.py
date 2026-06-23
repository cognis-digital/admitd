"""Exhaustive rule-verb + engine-behavior matrix for admitd.

Standard library only, no network. This suite drives every built-in policy and
every rule verb through positive and negative cases, exercises the
container-group handling (init / ephemeral), the JSON-pointer locations, the
severity sort, the gate logic, the serializers (JSON / SARIF / JUnit), the
AdmissionReview unwrap, and the mutate-patch synthesis. It complements the
smoke/deep suites and is intended to lock down behavior across refactors.
"""

import base64
import json
import os
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from admitd import (  # noqa: E402
    SEVERITY_ORDER,
    admission_response,
    all_policies,
    builtin_policies,
    decisions_to_dict,
    evaluate_object,
    evaluate_text,
    parse_objects,
    policy_from_dict,
    to_junit,
    to_sarif,
)
from admitd.core import (  # noqa: E402
    Decision,
    Patch,
    Violation,
    _split_image,
    decision_uid,
    load_policies_dir,
)
from admitd.cli import main  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(REPO_ROOT, "demos")


def _pod(spec):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"}, "spec": spec}


def _ids(decision):
    return {v.policy_id for v in decision.violations}


def _one_policy(verb, spec, action="deny", severity="high", kinds=None):
    d = {"id": "ADMITD-TEST", "title": "t", "severity": severity,
         "control": "ctrl", "action": action, "rules": [{verb: spec}]}
    if kinds is not None:
        d["match"] = {"kinds": kinds}
    return policy_from_dict(d)


class TestForbidField(unittest.TestCase):
    def test_fires_on_exact_value(self):
        pol = _one_policy("forbid_field",
                          {"path": "securityContext.privileged", "equals": True})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "securityContext": {"privileged": True}}]}), [pol])
        self.assertFalse(d.allowed)
        self.assertEqual(len(d.violations), 1)

    def test_no_fire_when_value_differs(self):
        pol = _one_policy("forbid_field",
                          {"path": "securityContext.privileged", "equals": True})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "securityContext": {"privileged": False}}]}), [pol])
        self.assertTrue(d.allowed)
        self.assertEqual(len(d.violations), 0)

    def test_any_value_mode_fires_on_presence(self):
        # No "equals" => fire if the field is present at all.
        pol = _one_policy("forbid_field", {"path": "securityContext.runAsUser"})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "securityContext": {"runAsUser": 0}}]}), [pol])
        self.assertFalse(d.allowed)

    def test_location_points_at_container(self):
        pol = _one_policy("forbid_field",
                          {"path": "securityContext.privileged", "equals": True})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "securityContext": {"privileged": True}}]}), [pol])
        self.assertEqual(d.violations[0].location,
                         "/spec/containers/0/securityContext/privileged")


class TestRequireField(unittest.TestCase):
    def test_missing_field_fires(self):
        pol = _one_policy("require_field",
                          {"path": "securityContext.runAsNonRoot", "equals": True})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertFalse(d.allowed)

    def test_present_matching_value_ok(self):
        pol = _one_policy("require_field",
                          {"path": "securityContext.runAsNonRoot", "equals": True})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "securityContext": {"runAsNonRoot": True}}]}), [pol])
        self.assertTrue(d.allowed)

    def test_present_wrong_value_fires(self):
        pol = _one_policy("require_field",
                          {"path": "securityContext.runAsNonRoot", "equals": True})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "securityContext": {"runAsNonRoot": False}}]}), [pol])
        self.assertFalse(d.allowed)

    def test_nested_path_present_ok(self):
        pol = _one_policy("require_field",
                          {"path": "securityContext.seccompProfile.type",
                           "equals": "RuntimeDefault"})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1",
             "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}}}]}), [pol])
        self.assertTrue(d.allowed)


class TestPodFields(unittest.TestCase):
    def test_forbid_pod_field_fires(self):
        pol = _one_policy("forbid_pod_field", {"path": "hostNetwork", "equals": True})
        d = evaluate_object(_pod({"hostNetwork": True,
                                  "containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertFalse(d.allowed)
        self.assertEqual(d.violations[0].location, "/spec/hostNetwork")

    def test_forbid_pod_field_absent_ok(self):
        pol = _one_policy("forbid_pod_field", {"path": "hostNetwork", "equals": True})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertTrue(d.allowed)

    def test_require_pod_field_missing_fires(self):
        pol = _one_policy("require_pod_field",
                          {"path": "automountServiceAccountToken", "equals": False})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertFalse(d.allowed)

    def test_require_pod_field_present_ok(self):
        pol = _one_policy("require_pod_field",
                          {"path": "automountServiceAccountToken", "equals": False})
        d = evaluate_object(_pod({"automountServiceAccountToken": False,
                                  "containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertTrue(d.allowed)


class TestImageTag(unittest.TestCase):
    def test_latest_explicit_fires(self):
        pol = _one_policy("forbid_image_tag", {"tags": ["latest"], "untagged": True})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "nginx:latest"}]}), [pol])
        self.assertFalse(d.allowed)

    def test_untagged_fires(self):
        pol = _one_policy("forbid_image_tag", {"tags": ["latest"], "untagged": True})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "redis"}]}), [pol])
        self.assertFalse(d.allowed)

    def test_untagged_ignored_when_disabled(self):
        pol = _one_policy("forbid_image_tag", {"tags": ["latest"], "untagged": False})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "redis"}]}), [pol])
        self.assertTrue(d.allowed)

    def test_pinned_tag_ok(self):
        pol = _one_policy("forbid_image_tag", {"tags": ["latest"], "untagged": True})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "redis:7.2"}]}), [pol])
        self.assertTrue(d.allowed)

    def test_digest_ok(self):
        pol = _one_policy("forbid_image_tag", {"tags": ["latest"], "untagged": True})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "redis@sha256:" + "b" * 64}]}), [pol])
        self.assertTrue(d.allowed)

    def test_case_insensitive_tag(self):
        pol = _one_policy("forbid_image_tag", {"tags": ["LATEST"], "untagged": False})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:Latest"}]}), [pol])
        self.assertFalse(d.allowed)


class TestSplitImage(unittest.TestCase):
    def test_plain_tag(self):
        self.assertEqual(_split_image("nginx:1.25"), ("nginx", "1.25"))

    def test_registry_port(self):
        self.assertEqual(_split_image("reg:5000/a/b:2"), ("reg:5000/a/b", "2"))

    def test_registry_port_untagged(self):
        self.assertEqual(_split_image("reg:5000/a/b"), ("reg:5000/a/b", ""))

    def test_digest(self):
        repo, tag = _split_image("a/b@sha256:deadbeef")
        self.assertEqual(repo, "a/b")
        self.assertEqual(tag, "sha256:deadbeef")

    def test_bare(self):
        self.assertEqual(_split_image("busybox"), ("busybox", ""))


class TestRegistry(unittest.TestCase):
    def test_disallowed_registry_fires(self):
        pol = _one_policy("require_registry", {"allowed": ["registry.internal/"]})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "docker.io/library/nginx:1"}]}), [pol])
        self.assertFalse(d.allowed)

    def test_allowed_registry_ok(self):
        pol = _one_policy("require_registry", {"allowed": ["registry.internal/"]})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "registry.internal/nginx:1"}]}), [pol])
        self.assertTrue(d.allowed)

    def test_multiple_allowed_prefixes(self):
        pol = _one_policy("require_registry",
                          {"allowed": ["registry.internal/", "ghcr.io/cognis/"]})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "ghcr.io/cognis/app:1"}]}), [pol])
        self.assertTrue(d.allowed)

    def test_empty_allowed_is_noop(self):
        pol = _one_policy("require_registry", {"allowed": []})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "anywhere/x:1"}]}), [pol])
        self.assertTrue(d.allowed)


class TestDropCaps(unittest.TestCase):
    def test_drop_all_satisfies(self):
        pol = _one_policy("require_drop_caps", {"caps": ["NET_RAW"]})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1",
             "securityContext": {"capabilities": {"drop": ["ALL"]}}}]}), [pol])
        self.assertTrue(d.allowed)

    def test_missing_specific_cap_fires(self):
        pol = _one_policy("require_drop_caps", {"caps": ["NET_RAW", "SYS_ADMIN"]})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1",
             "securityContext": {"capabilities": {"drop": ["NET_RAW"]}}}]}), [pol])
        self.assertFalse(d.allowed)
        self.assertIn("SYS_ADMIN", d.violations[0].message)

    def test_case_insensitive_caps(self):
        pol = _one_policy("require_drop_caps", {"caps": ["net_raw"]})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1",
             "securityContext": {"capabilities": {"drop": ["NET_RAW"]}}}]}), [pol])
        self.assertTrue(d.allowed)

    def test_no_securitycontext_fires(self):
        pol = _one_policy("require_drop_caps", {"caps": ["ALL"]})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertFalse(d.allowed)


class TestVolumeType(unittest.TestCase):
    def test_hostpath_fires(self):
        pol = _one_policy("forbid_volume_type", {"types": ["hostPath"]})
        d = evaluate_object(_pod({
            "volumes": [{"name": "h", "hostPath": {"path": "/etc"}}],
            "containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertFalse(d.allowed)
        self.assertEqual(d.violations[0].location, "/spec/volumes/0/hostPath")

    def test_configmap_volume_ok(self):
        pol = _one_policy("forbid_volume_type", {"types": ["hostPath"]})
        d = evaluate_object(_pod({
            "volumes": [{"name": "cm", "configMap": {"name": "x"}}],
            "containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertTrue(d.allowed)

    def test_multiple_forbidden_types(self):
        pol = _one_policy("forbid_volume_type", {"types": ["hostPath", "nfs"]})
        d = evaluate_object(_pod({
            "volumes": [{"name": "n", "nfs": {"server": "s", "path": "/"}}],
            "containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertFalse(d.allowed)


class TestResourceLimits(unittest.TestCase):
    def test_missing_both_fires(self):
        pol = _one_policy("require_resource_limits", {"resources": ["cpu", "memory"]})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertFalse(d.allowed)

    def test_partial_limits_fires(self):
        pol = _one_policy("require_resource_limits", {"resources": ["cpu", "memory"]})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "resources": {"limits": {"cpu": "100m"}}}]}), [pol])
        self.assertFalse(d.allowed)
        self.assertIn("memory", d.violations[0].message)

    def test_full_limits_ok(self):
        pol = _one_policy("require_resource_limits", {"resources": ["cpu", "memory"]})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1",
             "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}}}]}), [pol])
        self.assertTrue(d.allowed)

    def test_ephemeral_skipped(self):
        pol = _one_policy("require_resource_limits", {"resources": ["cpu"]})
        d = evaluate_object(_pod({
            "containers": [{"name": "c", "image": "x:1",
                            "resources": {"limits": {"cpu": "1"}}}],
            "ephemeralContainers": [{"name": "dbg", "image": "debug:1"}]}), [pol])
        self.assertTrue(d.allowed)


class TestContainerGroups(unittest.TestCase):
    def test_init_container_checked(self):
        d = evaluate_object(_pod({
            "initContainers": [{"name": "i", "image": "x:1",
                                "securityContext": {"privileged": True}}],
            "containers": [{"name": "c", "image": "registry.internal/a:1.0",
                            "securityContext": {
                                "privileged": False, "runAsNonRoot": True,
                                "readOnlyRootFilesystem": True,
                                "allowPrivilegeEscalation": False,
                                "seccompProfile": {"type": "RuntimeDefault"},
                                "capabilities": {"drop": ["ALL"]}},
                            "resources": {"limits": {"cpu": "1", "memory": "1Mi"}}}]}),
            builtin_policies())
        locs = {v.location for v in d.violations}
        self.assertTrue(any(l.startswith("/spec/initContainers/0") for l in locs))

    def test_multiple_containers_each_evaluated(self):
        pol = _one_policy("forbid_image_tag", {"tags": ["latest"], "untagged": True})
        d = evaluate_object(_pod({"containers": [
            {"name": "a", "image": "x:latest"},
            {"name": "b", "image": "y:latest"}]}), [pol])
        self.assertEqual(len(d.violations), 2)


class TestMatchKinds(unittest.TestCase):
    def test_policy_scoped_to_kind(self):
        pol = _one_policy("forbid_field",
                          {"path": "securityContext.privileged", "equals": True},
                          kinds=["DaemonSet"])
        # A privileged Pod should NOT trip a DaemonSet-only policy.
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "securityContext": {"privileged": True}}]}), [pol])
        self.assertTrue(d.allowed)

    def test_policy_applies_to_listed_kind(self):
        pol = _one_policy("forbid_field",
                          {"path": "securityContext.privileged", "equals": True},
                          kinds=["DaemonSet"])
        obj = {"kind": "DaemonSet", "metadata": {"name": "ds"},
               "spec": {"template": {"spec": {"containers": [
                   {"name": "c", "image": "x:1", "securityContext": {"privileged": True}}]}}}}
        d = evaluate_object(obj, [pol])
        self.assertFalse(d.allowed)


class TestSeveritySortAndCounts(unittest.TestCase):
    def test_sorted_critical_first(self):
        d = evaluate_object(_pod({
            "hostNetwork": True,
            "containers": [{"name": "c", "image": "x:latest",
                            "securityContext": {"privileged": True}}]}),
            builtin_policies())
        sevs = [SEVERITY_ORDER[v.severity] for v in d.violations]
        self.assertEqual(sevs, sorted(sevs))
        self.assertEqual(d.violations[0].severity, "critical")

    def test_counts_match_violations(self):
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:latest"}]}), builtin_policies())
        self.assertEqual(sum(d.counts.values()), len(d.violations))


class TestActions(unittest.TestCase):
    def test_warn_action_does_not_deny(self):
        pol = _one_policy("require_field",
                          {"path": "metadata.labels.team"}, action="warn")
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertTrue(d.allowed)            # warn never denies
        self.assertEqual(len(d.warn_violations), 1)

    def test_deny_action_denies(self):
        pol = _one_policy("forbid_field",
                          {"path": "securityContext.privileged", "equals": True})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "securityContext": {"privileged": True}}]}), [pol])
        self.assertFalse(d.allowed)
        self.assertEqual(len(d.deny_violations), 1)


class TestMutateSynthesis(unittest.TestCase):
    def test_require_field_becomes_patch(self):
        pol = policy_from_dict({
            "id": "M1", "title": "m", "severity": "low", "action": "mutate",
            "rules": [{"require_field": {"path": "securityContext.runAsNonRoot",
                                         "equals": True}}]})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:1"}]}), [pol])
        self.assertTrue(d.allowed)
        self.assertEqual(len(d.violations), 0)
        paths = {p.path for p in d.patches}
        self.assertIn("/spec/containers/0/securityContext/runAsNonRoot", paths)

    def test_drop_caps_becomes_patch(self):
        pol = policy_from_dict({
            "id": "M2", "title": "m", "severity": "low", "action": "mutate",
            "rules": [{"require_drop_caps": {"caps": ["ALL"]}}]})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:1"}]}), [pol])
        drop = [p for p in d.patches
                if p.path.endswith("/securityContext/capabilities/drop")]
        self.assertEqual(len(drop), 1)
        self.assertEqual(drop[0].value, ["ALL"])

    def test_no_patch_when_already_satisfied(self):
        pol = policy_from_dict({
            "id": "M3", "title": "m", "severity": "low", "action": "mutate",
            "rules": [{"require_drop_caps": {"caps": ["ALL"]}}]})
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1",
             "securityContext": {"capabilities": {"drop": ["ALL"]}}}]}), [pol])
        self.assertEqual(len(d.patches), 0)


class TestParsing(unittest.TestCase):
    def test_json_single_object(self):
        objs = parse_objects(json.dumps(_pod({"containers": []})))
        self.assertEqual(len(objs), 1)

    def test_json_array(self):
        objs = parse_objects(json.dumps([_pod({"containers": []}),
                                         _pod({"containers": []})]))
        self.assertEqual(len(objs), 2)

    def test_list_kind(self):
        wrapper = {"kind": "List", "items": [_pod({"containers": []})]}
        objs = parse_objects(json.dumps(wrapper))
        self.assertEqual(len(objs), 1)

    def test_admissionreview_unwrap(self):
        review = {"kind": "AdmissionReview",
                  "request": {"uid": "u-1", "object": _pod({"containers": []})}}
        objs = parse_objects(json.dumps(review))
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0][0]["kind"], "Pod")

    def test_empty_text(self):
        self.assertEqual(parse_objects(""), [])

    def test_yaml_inline_flow(self):
        text = ("kind: Pod\nmetadata:\n  name: y\nspec:\n  containers:\n"
                "    - name: c\n      image: x:1\n      securityContext:\n"
                "        capabilities:\n          drop: [ALL]\n")
        obj, _ = parse_objects(text)[0]
        self.assertEqual(
            obj["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"],
            ["ALL"])


class TestSerializers(unittest.TestCase):
    def setUp(self):
        self.decisions = evaluate_text(
            json.dumps(_pod({"hostNetwork": True, "containers": [
                {"name": "c", "image": "x:latest",
                 "securityContext": {"privileged": True}}]})),
            builtin_policies())

    def test_aggregate_dict_shape(self):
        agg = decisions_to_dict(self.decisions)
        self.assertEqual(agg["tool"], "admitd")
        self.assertFalse(agg["allowed"])
        self.assertGreater(agg["total_violations"], 0)
        self.assertEqual(agg["objects_evaluated"], 1)
        self.assertEqual(agg["objects_denied"], 1)

    def test_sarif_levels_and_rules(self):
        doc = to_sarif(self.decisions)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
        used = {r["ruleId"] for r in run["results"]}
        self.assertTrue(used.issubset(declared))
        for r in run["tool"]["driver"]["rules"]:
            self.assertIn("security-severity", r["properties"])

    def test_junit_parses_and_has_failures(self):
        xml = to_junit(self.decisions)
        root = ET.fromstring(xml)
        self.assertEqual(root.tag, "testsuites")
        failures = root.findall(".//failure")
        self.assertGreater(len(failures), 0)

    def test_junit_passing_object_has_no_failure(self):
        clean = evaluate_text(json.dumps(_pod({"containers": [
            {"name": "c", "image": "registry.internal/a:1.0",
             "securityContext": {
                 "privileged": False, "allowPrivilegeEscalation": False,
                 "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                 "seccompProfile": {"type": "RuntimeDefault"},
                 "capabilities": {"drop": ["ALL"]}},
             "resources": {"limits": {"cpu": "1", "memory": "1Mi"}}}]})),
            builtin_policies())
        root = ET.fromstring(to_junit(clean))
        self.assertEqual(len(root.findall(".//failure")), 0)


class TestAdmissionResponse(unittest.TestCase):
    def test_deny_response_has_403(self):
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "x:1", "securityContext": {"privileged": True}}]}),
            builtin_policies())
        resp = admission_response(d, uid="abc")["response"]
        self.assertEqual(resp["uid"], "abc")
        self.assertFalse(resp["allowed"])
        self.assertEqual(resp["status"]["code"], 403)

    def test_allow_response(self):
        d = evaluate_object(_pod({"containers": [
            {"name": "c", "image": "registry.internal/a:1.0",
             "securityContext": {
                 "privileged": False, "allowPrivilegeEscalation": False,
                 "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                 "seccompProfile": {"type": "RuntimeDefault"},
                 "capabilities": {"drop": ["ALL"]}},
             "resources": {"limits": {"cpu": "1", "memory": "1Mi"}}}]}),
            builtin_policies())
        resp = admission_response(d)["response"]
        self.assertTrue(resp["allowed"])

    def test_mutate_patch_is_base64_jsonpatch(self):
        pol = policy_from_dict({
            "id": "M", "title": "m", "severity": "low", "action": "mutate",
            "rules": [{"require_field": {"path": "securityContext.runAsNonRoot",
                                         "equals": True}}]})
        d = evaluate_object(_pod({"containers": [{"name": "c", "image": "x:1"}]}), [pol])
        resp = admission_response(d)["response"]
        self.assertEqual(resp["patchType"], "JSONPatch")
        ops = json.loads(base64.b64decode(resp["patch"]))
        self.assertTrue(any(o["path"].endswith("runAsNonRoot") for o in ops))

    def test_uid_is_deterministic(self):
        d = Decision(kind="Pod", name="p", namespace="ns")
        self.assertEqual(decision_uid(d), decision_uid(d))


class TestBuiltinLibrary(unittest.TestCase):
    def test_ten_policies_unique_ids(self):
        pols = builtin_policies()
        self.assertGreaterEqual(len(pols), 10)
        self.assertEqual(len(pols), len({p.id for p in pols}))

    def test_all_have_control_mapping(self):
        for p in builtin_policies():
            self.assertTrue(p.control, p.id)

    def test_severities_are_valid(self):
        for p in builtin_policies():
            self.assertIn(p.severity, SEVERITY_ORDER)

    def test_fully_insecure_pod_trips_many(self):
        d = evaluate_object(_pod({
            "hostNetwork": True, "hostPID": True, "hostIPC": True,
            "volumes": [{"name": "h", "hostPath": {"path": "/"}}],
            "containers": [{"name": "c", "image": "nginx:latest",
                            "securityContext": {"privileged": True,
                                                "allowPrivilegeEscalation": True}}]}),
            builtin_policies())
        ids = _ids(d)
        for expected in ("ADMITD-PRIV-001", "ADMITD-PRIVESC-002", "ADMITD-HOSTNS-003",
                         "ADMITD-HOSTPATH-004", "ADMITD-NONROOT-005", "ADMITD-LATEST-008"):
            self.assertIn(expected, ids)


class TestPolicyLoading(unittest.TestCase):
    def test_no_builtin_empty(self):
        self.assertEqual(all_policies(include_builtin=False), [])

    def test_load_dir_with_policies_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bundle.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"policies": [
                    {"id": "P1", "title": "a", "severity": "low", "action": "deny",
                     "rules": [{"forbid_pod_field": {"path": "hostPID", "equals": True}}]},
                    {"id": "P2", "title": "b", "severity": "low", "action": "deny",
                     "rules": [{"forbid_pod_field": {"path": "hostIPC", "equals": True}}]},
                ]}, fh)
            pols = load_policies_dir(tmp)
            self.assertEqual({p.id for p in pols}, {"P1", "P2"})

    def test_invalid_policy_missing_id(self):
        from admitd.core import PolicyError
        with self.assertRaises(PolicyError):
            policy_from_dict({"title": "no id"})

    def test_bad_severity_defaults_medium(self):
        p = policy_from_dict({"id": "X", "severity": "spicy", "rules": []})
        self.assertEqual(p.severity, "medium")

    def test_bad_action_defaults_deny(self):
        p = policy_from_dict({"id": "X", "action": "nuke", "rules": []})
        self.assertEqual(p.action, "deny")


class TestCliGate(unittest.TestCase):
    def _write(self, tmp, obj):
        path = os.path.join(tmp, "m.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return path

    def test_fail_on_high_skips_low_only(self):
        only_limits = _pod({"containers": [
            {"name": "c", "image": "registry.internal/a:1.0",
             "securityContext": {
                 "privileged": False, "allowPrivilegeEscalation": False,
                 "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                 "seccompProfile": {"type": "RuntimeDefault"},
                 "capabilities": {"drop": ["ALL"]}}}]})  # only missing limits (low)
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, only_limits)
            self.assertEqual(main(["eval", path, "--fail-on", "high"]), 0)
            self.assertEqual(main(["eval", path, "--fail-on", "low"]), 1)

    def test_junit_format_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, _pod({"containers": [
                {"name": "c", "image": "x:latest"}]}))
            out = os.path.join(tmp, "j.xml")
            main(["eval", path, "--format", "junit", "--out", out])
            root = ET.parse(out).getroot()
            self.assertEqual(root.tag, "testsuites")


if __name__ == "__main__":
    unittest.main()
