"""Tests for the JUnit XML exporter and the bundled demo scenarios.

Standard library only, no network. These guard two things:
  * ``to_junit`` produces well-formed, schema-shaped JUnit XML, and
  * every demo under ``demos/`` actually fires the verdict its SCENARIO claims.
"""

import os
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from admitd import (  # noqa: E402
    all_policies,
    builtin_policies,
    evaluate_object,
    to_junit,
)
from admitd.core import evaluate_file  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(REPO_ROOT, "demos")


def _pod(spec):
    return {"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "p", "namespace": "default"}, "spec": spec}


class TestJUnit(unittest.TestCase):
    def setUp(self):
        self.policies = builtin_policies()

    def test_wellformed_and_counts(self):
        insecure = evaluate_object(
            _pod({"containers": [{"name": "c", "image": "nginx:latest",
                                  "securityContext": {"privileged": True}}]}),
            self.policies,
        )
        hardened = evaluate_object(
            _pod({"containers": [{
                "name": "c", "image": "registry.internal/a:1.0",
                "securityContext": {
                    "privileged": False, "allowPrivilegeEscalation": False,
                    "runAsNonRoot": True, "readOnlyRootFilesystem": True,
                    "seccompProfile": {"type": "RuntimeDefault"},
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
            }]}),
            self.policies,
        )
        xml = to_junit([insecure, hardened])
        root = ET.fromstring(xml)  # raises if malformed
        self.assertEqual(root.tag, "testsuites")
        self.assertEqual(root.attrib["tests"], "2")
        cases = root.findall(".//testcase")
        self.assertEqual(len(cases), 2)
        failures = root.findall(".//failure")
        # The insecure pod has >=1 violation; the hardened pod has none.
        self.assertEqual(len(failures), len(insecure.violations))
        self.assertGreater(len(failures), 0)
        self.assertEqual(root.attrib["failures"], str(len(insecure.violations)))

    def test_empty_decisions(self):
        root = ET.fromstring(to_junit([]))
        self.assertEqual(root.attrib["tests"], "0")
        self.assertEqual(root.attrib["failures"], "0")

    def test_xml_escaping(self):
        # Inject characters that must be escaped via a policy title/message.
        pol = all_policies(include_builtin=False)
        from admitd import policy_from_dict
        p = policy_from_dict({
            "id": "X&<>\"01", "title": "deny <bad> & \"quoted\"",
            "severity": "high", "action": "deny",
            "rules": [{"forbid_field": {"path": "securityContext.privileged",
                                        "equals": True}}],
        }, source="<test>")
        d = evaluate_object(
            _pod({"containers": [{"name": "c", "image": "x:1.0",
                                  "securityContext": {"privileged": True}}]}),
            [p],
        )
        xml = to_junit([d])
        # Must still parse despite the angle brackets/ampersands/quotes.
        root = ET.fromstring(xml)
        self.assertEqual(len(root.findall(".//failure")), 1)

    def test_cli_junit_format(self):
        proc = subprocess.run(
            [sys.executable, "-m", "admitd", "eval",
             os.path.join(DEMOS, "10-helm-rendered-bundle", "rendered.json"),
             "--format", "junit"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        # Gate trips (privileged Job) -> exit 1, but XML is on stdout.
        self.assertEqual(proc.returncode, 1, proc.stderr)
        root = ET.fromstring(proc.stdout)
        self.assertEqual(root.attrib["tests"], "2")


class TestDemosFire(unittest.TestCase):
    """Each demo must produce the verdict its SCENARIO.md promises."""

    def _deny_ids(self, path, policies):
        decisions = evaluate_file(path, policies)
        return decisions, {v.policy_id for d in decisions for v in d.violations}

    def test_02_deployment_sidecar_denied(self):
        decisions, ids = self._deny_ids(
            os.path.join(DEMOS, "02-deployment-multidoc", "app-bundle.yaml"),
            builtin_policies())
        # 3 objects; only the Deployment (forgotten sidecar) is denied.
        self.assertEqual(len(decisions), 3)
        denied = [d for d in decisions if not d.allowed]
        self.assertEqual(len(denied), 1)
        self.assertIn("ADMITD-NONROOT-005", ids)

    def test_03_cronjob_nested_podspec(self):
        _, ids = self._deny_ids(
            os.path.join(DEMOS, "03-cronjob-batch", "nightly-report.yaml"),
            builtin_policies())
        self.assertIn("ADMITD-LATEST-008", ids)
        self.assertIn("ADMITD-NONROOT-005", ids)

    def test_04_daemonset_hostpath(self):
        _, ids = self._deny_ids(
            os.path.join(DEMOS, "04-daemonset-node-agent", "log-collector.yaml"),
            builtin_policies())
        self.assertIn("ADMITD-HOSTPATH-004", ids)
        self.assertIn("ADMITD-HOSTNS-003", ids)

    def test_05_custom_registry_only(self):
        pols = all_policies(
            extra_dir=os.path.join(DEMOS, "05-custom-registry-policy", "policies"),
            include_builtin=False)
        decisions, ids = self._deny_ids(
            os.path.join(DEMOS, "05-custom-registry-policy", "deployment.yaml"),
            pols)
        self.assertEqual(ids, {"ACME-REGISTRY-001"})
        self.assertFalse(decisions[0].allowed)

    def test_06_mutate_emits_patches(self):
        pols = all_policies(
            extra_dir=os.path.join(DEMOS, "06-mutate-autoremediate", "policies",
                                   "mutate-hardening.yaml"),
            include_builtin=False)
        decisions = evaluate_file(
            os.path.join(DEMOS, "06-mutate-autoremediate", "under-hardened-pod.yaml"),
            pols)
        self.assertTrue(decisions[0].allowed)
        self.assertGreater(len(decisions[0].patches), 0)

    def test_07_admissionreview_unwrapped_and_denied(self):
        decisions, ids = self._deny_ids(
            os.path.join(DEMOS, "07-admissionreview-deny",
                         "review-privileged-daemonset.json"),
            builtin_policies())
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0].kind, "DaemonSet")
        self.assertIn("ADMITD-PRIV-001", ids)

    def test_08_statefulset_only_limits(self):
        decisions, ids = self._deny_ids(
            os.path.join(DEMOS, "08-statefulset-database", "postgres.yaml"),
            builtin_policies())
        self.assertEqual(ids, {"ADMITD-LIMITS-009"})

    def test_09_warn_does_not_deny(self):
        pols = all_policies(
            extra_dir=os.path.join(DEMOS, "09-warn-vs-deny-gate", "policies"),
            include_builtin=True)
        decisions = evaluate_file(
            os.path.join(DEMOS, "09-warn-vs-deny-gate", "web.yaml"), pols)
        # Hardened workload: warn-only finding, so it is still allowed.
        self.assertTrue(decisions[0].allowed)
        self.assertTrue(any(v.action == "warn" for v in decisions[0].violations))

    def test_10_helm_list_flattened(self):
        decisions, _ = self._deny_ids(
            os.path.join(DEMOS, "10-helm-rendered-bundle", "rendered.json"),
            builtin_policies())
        self.assertEqual(len(decisions), 2)
        kinds = {d.kind for d in decisions}
        self.assertEqual(kinds, {"Deployment", "Job"})


if __name__ == "__main__":
    unittest.main()
