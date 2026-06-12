"""Smoke tests for admitd. Standard library only, no network."""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from admitd import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    builtin_policies,
    evaluate_object,
)
from admitd.cli import main  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(REPO_ROOT, "demos", "01-basic")


def _pod(spec):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"}, "spec": spec}


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "admitd")
        self.assertTrue(TOOL_VERSION)

    def test_builtins_loaded(self):
        pols = builtin_policies()
        self.assertGreaterEqual(len(pols), 10)
        ids = {p.id for p in pols}
        self.assertIn("ADMITD-PRIV-001", ids)


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.policies = builtin_policies()

    def _rules(self, obj):
        return {v.policy_id for v in evaluate_object(obj, self.policies).violations}

    def test_privileged_is_denied(self):
        obj = _pod({"containers": [{"name": "c", "image": "x:1.0",
                                    "securityContext": {"privileged": True}}]})
        d = evaluate_object(obj, self.policies)
        self.assertFalse(d.allowed)
        self.assertIn("ADMITD-PRIV-001", self._rules(obj))

    def test_host_namespaces_denied(self):
        obj = _pod({"hostNetwork": True, "hostPID": True,
                    "containers": [{"name": "c", "image": "x:1.0"}]})
        self.assertIn("ADMITD-HOSTNS-003", self._rules(obj))

    def test_hostpath_volume_denied(self):
        obj = _pod({"volumes": [{"name": "h", "hostPath": {"path": "/"}}],
                    "containers": [{"name": "c", "image": "x:1.0"}]})
        self.assertIn("ADMITD-HOSTPATH-004", self._rules(obj))

    def test_latest_tag_denied(self):
        obj = _pod({"containers": [{"name": "c", "image": "nginx:latest"}]})
        self.assertIn("ADMITD-LATEST-008", self._rules(obj))

    def test_untagged_image_denied(self):
        obj = _pod({"containers": [{"name": "c", "image": "redis"}]})
        self.assertIn("ADMITD-LATEST-008", self._rules(obj))

    def test_digest_pinned_image_ok(self):
        obj = _pod({"containers": [{"name": "c",
                                    "image": "registry.internal/a@sha256:" + "a" * 64}]})
        self.assertNotIn("ADMITD-LATEST-008", self._rules(obj))

    def test_fully_hardened_pod_allowed(self):
        obj = _pod({"containers": [{
            "name": "c", "image": "registry.internal/a:1.0",
            "securityContext": {
                "privileged": False, "allowPrivilegeEscalation": False,
                "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                "seccompProfile": {"type": "RuntimeDefault"},
                "capabilities": {"drop": ["ALL"]},
            },
            "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
        }]})
        d = evaluate_object(obj, self.policies)
        self.assertTrue(d.allowed, d.to_dict())
        self.assertEqual(len(d.violations), 0)

    def test_non_workload_kind_allowed(self):
        obj = {"apiVersion": "v1", "kind": "ConfigMap",
               "metadata": {"name": "cm"}, "data": {"k": "v"}}
        d = evaluate_object(obj, self.policies)
        self.assertTrue(d.allowed)


class TestCli(unittest.TestCase):
    def test_eval_insecure_pod_fails(self):
        proc = subprocess.run(
            [sys.executable, "-m", "admitd", "eval",
             os.path.join(DEMO, "insecure-pod.yaml"), "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertFalse(data["allowed"])
        ids = {v["policy_id"] for d in data["decisions"] for v in d["violations"]}
        self.assertIn("ADMITD-PRIV-001", ids)

    def test_eval_hardened_pod_passes(self):
        rc = main(["eval", os.path.join(DEMO, "hardened-pod.yaml")])
        self.assertEqual(rc, 0)

    def test_eval_admissionreview_unwraps(self):
        rc = main(["eval", os.path.join(DEMO, "admissionreview.json")])
        self.assertEqual(rc, 1)  # the embedded pod is privileged

    def test_policies_subcommand(self):
        self.assertEqual(main(["policies"]), 0)

    def test_missing_file_exits_2(self):
        self.assertEqual(main(["eval", "/no/such/manifest.yaml"]), 2)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()
