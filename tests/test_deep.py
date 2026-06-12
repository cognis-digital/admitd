"""Deep behavior tests for admitd — YAML parsing, mutate, SARIF, webhook, MCP.

Standard library only, no network beyond localhost self-requests.
"""

import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from admitd import (  # noqa: E402
    all_policies,
    builtin_policies,
    evaluate_object,
    evaluate_text,
    parse_objects,
    policy_from_dict,
    to_sarif,
    admission_response,
)
from admitd.core import load_policies_dir, _split_image  # noqa: E402
from admitd.cli import main  # noqa: E402
from admitd import mcp_server, server  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(REPO_ROOT, "demos", "01-basic")


class TestYamlSubset(unittest.TestCase):
    def test_parse_pod_yaml(self):
        text = """
apiVersion: v1
kind: Pod
metadata:
  name: y
  namespace: default
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:1.25
      securityContext:
        privileged: false
"""
        objs = parse_objects(text)
        self.assertEqual(len(objs), 1)
        obj, _ = objs[0]
        self.assertEqual(obj["kind"], "Pod")
        self.assertIs(obj["spec"]["hostNetwork"], True)
        self.assertEqual(obj["spec"]["containers"][0]["image"], "nginx:1.25")
        self.assertIs(obj["spec"]["containers"][0]["securityContext"]["privileged"], False)

    def test_multidoc_yaml(self):
        text = "kind: Pod\nmetadata:\n  name: a\nspec:\n  containers: []\n---\nkind: Pod\nmetadata:\n  name: b\nspec:\n  containers: []\n"
        objs = parse_objects(text)
        self.assertEqual(len(objs), 2)
        self.assertEqual({o["metadata"]["name"] for o, _ in objs}, {"a", "b"})

    def test_flow_sequence(self):
        text = "kind: Pod\nmetadata:\n  name: c\nspec:\n  containers:\n    - name: x\n      image: a:1\n      securityContext:\n        capabilities:\n          drop: [ALL]\n"
        obj, _ = parse_objects(text)[0]
        self.assertEqual(
            obj["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"],
            ["ALL"],
        )


class TestImageSplit(unittest.TestCase):
    def test_registry_port_not_tag(self):
        repo, tag = _split_image("registry.local:5000/team/app:1.2")
        self.assertEqual(repo, "registry.local:5000/team/app")
        self.assertEqual(tag, "1.2")

    def test_digest(self):
        repo, tag = _split_image("a/b@sha256:abc")
        self.assertEqual(tag, "sha256:abc")

    def test_untagged(self):
        repo, tag = _split_image("redis")
        self.assertEqual(tag, "")


class TestWorkloadKinds(unittest.TestCase):
    def test_deployment_nested_podspec(self):
        obj = {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "d"},
            "spec": {"template": {"spec": {"containers": [
                {"name": "c", "image": "x:latest", "securityContext": {"privileged": True}}
            ]}}},
        }
        d = evaluate_object(obj, builtin_policies())
        self.assertFalse(d.allowed)
        locs = {v.location for v in d.violations}
        self.assertTrue(any(l.startswith("/spec/template/spec/containers/0") for l in locs))

    def test_cronjob_deep_podspec(self):
        obj = {
            "kind": "CronJob", "metadata": {"name": "cj"},
            "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [
                {"name": "c", "image": "x:latest"}
            ]}}}}},
        }
        d = evaluate_object(obj, builtin_policies())
        self.assertFalse(d.allowed)


class TestMutate(unittest.TestCase):
    def test_mutate_synthesizes_patches(self):
        pol = policy_from_dict({
            "id": "ADMITD-MUT-1", "title": "inject", "severity": "medium",
            "action": "mutate",
            "rules": [
                {"require_field": {"path": "securityContext.runAsNonRoot", "equals": True}},
                {"require_drop_caps": {"caps": ["ALL"]}},
            ],
        })
        obj = {"kind": "Pod", "metadata": {"name": "p"},
               "spec": {"containers": [{"name": "c", "image": "x:1"}]}}
        d = evaluate_object(obj, [pol])
        self.assertTrue(d.allowed)            # mutate emits no deny violations
        self.assertTrue(d.patches)
        paths = {p.path for p in d.patches}
        self.assertIn("/spec/containers/0/securityContext/runAsNonRoot", paths)
        self.assertIn("/spec/containers/0/securityContext/capabilities/drop", paths)

    def test_admission_response_carries_patch(self):
        pol = policy_from_dict({
            "id": "ADMITD-MUT-2", "title": "inject", "severity": "low",
            "action": "mutate",
            "rules": [{"require_field": {"path": "securityContext.runAsNonRoot", "equals": True}}],
        })
        obj = {"kind": "Pod", "metadata": {"name": "p"},
               "spec": {"containers": [{"name": "c", "image": "x:1"}]}}
        d = evaluate_object(obj, [pol])
        resp = admission_response(d, uid="u1")["response"]
        self.assertTrue(resp["allowed"])
        self.assertEqual(resp["patchType"], "JSONPatch")
        import base64
        patch = json.loads(base64.b64decode(resp["patch"]))
        self.assertTrue(any(op["path"].endswith("runAsNonRoot") for op in patch))


class TestCustomPolicies(unittest.TestCase):
    def test_load_json_policy_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "reg.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"id": "ADMITD-REG-1", "title": "registry",
                           "severity": "high", "action": "deny",
                           "rules": [{"require_registry": {"allowed": ["registry.internal/"]}}]}, fh)
            pols = load_policies_dir(tmp)
            self.assertEqual(len(pols), 1)
            obj = {"kind": "Pod", "metadata": {"name": "p"},
                   "spec": {"containers": [{"name": "c", "image": "docker.io/redis:7"}]}}
            d = evaluate_object(obj, pols)
            self.assertFalse(d.allowed)
            self.assertEqual(d.violations[0].policy_id, "ADMITD-REG-1")

    def test_no_builtin_flag(self):
        pols = all_policies(include_builtin=False)
        self.assertEqual(pols, [])


class TestSarif(unittest.TestCase):
    def test_sarif_shape(self):
        decisions = evaluate_text(
            "kind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: x:latest\n      securityContext:\n        privileged: true\n",
            builtin_policies())
        doc = to_sarif(decisions)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "admitd")
        self.assertTrue(run["results"])
        declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
        used = {r["ruleId"] for r in run["results"]}
        self.assertTrue(used.issubset(declared))
        for res in run["results"]:
            self.assertIn(res["level"], ("error", "warning", "note"))


class TestCliGates(unittest.TestCase):
    def test_fail_on_low_trips_on_limits_only(self):
        # A pod that only violates the low-severity limits rule.
        obj = {
            "kind": "Pod", "metadata": {"name": "p"},
            "spec": {"containers": [{
                "name": "c", "image": "registry.internal/a:1.0",
                "securityContext": {
                    "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                    "allowPrivilegeEscalation": False, "privileged": False,
                    "seccompProfile": {"type": "RuntimeDefault"},
                    "capabilities": {"drop": ["ALL"]},
                },
            }]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "m.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(obj, fh)
            # default gate (deny actions present) → exit 1 (limits is a deny policy)
            self.assertEqual(main(["eval", p]), 1)
            # gate only on critical → passes
            self.assertEqual(main(["eval", p, "--fail-on", "critical"]), 0)

    def test_sarif_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.sarif")
            rc = main(["eval", os.path.join(DEMO, "insecure-pod.yaml"),
                       "--format", "sarif", "--out", out])
            self.assertEqual(rc, 1)
            with open(out, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["version"], "2.1.0")

    def test_policies_json(self):
        self.assertEqual(main(["policies", "--format", "json"]), 0)


class TestWebhook(unittest.TestCase):
    def test_self_test_denies_privileged(self):
        self.assertTrue(server.self_test(builtin_policies()))


class TestMcpServer(unittest.TestCase):
    def _roundtrip(self, requests):
        stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
        stdout = io.StringIO()
        mcp_server.run_mcp_server(stdin=stdin, stdout=stdout)
        return [json.loads(l) for l in stdout.getvalue().splitlines() if l.strip()]

    def test_initialize_and_list(self):
        out = self._roundtrip([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ])
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["result"]["serverInfo"]["name"], "admitd")
        names = {t["name"] for t in out[1]["result"]["tools"]}
        self.assertEqual(names, {"eval", "list_policies"})

    def test_tools_call_eval(self):
        manifest = json.dumps({"kind": "Pod", "metadata": {"name": "p"},
                               "spec": {"containers": [{"name": "c", "image": "x:latest",
                                        "securityContext": {"privileged": True}}]}})
        out = self._roundtrip([
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "eval", "arguments": {"manifest": manifest}}},
        ])
        res = out[0]["result"]
        self.assertTrue(res["isError"])
        payload = json.loads(res["content"][0]["text"])
        self.assertFalse(payload["allowed"])
        self.assertGreater(payload["total_violations"], 0)

    def test_tools_call_list_policies(self):
        out = self._roundtrip([
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "list_policies", "arguments": {}}},
        ])
        payload = json.loads(out[0]["result"]["content"][0]["text"])
        self.assertGreaterEqual(payload["count"], 10)

    def test_unknown_tool_is_error(self):
        out = self._roundtrip([
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "nope", "arguments": {}}},
        ])
        self.assertEqual(out[0]["error"]["code"], -32602)

    def test_parse_error(self):
        stdin = io.StringIO("{not json\n")
        stdout = io.StringIO()
        mcp_server.run_mcp_server(stdin=stdin, stdout=stdout)
        out = json.loads(stdout.getvalue().strip())
        self.assertEqual(out["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()
