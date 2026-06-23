// Smoke + behavior tests for the admitd Node port. Uses the Node built-in
// test runner (node:test) and assert — no third-party test dependencies.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  builtinPolicies, evaluateObject, evaluateText, parseObjects, splitImage,
  TOOL_NAME,
} from "../src/admitd.mjs";

const pod = (spec) => ({
  apiVersion: "v1", kind: "Pod",
  metadata: { name: "p", namespace: "default" }, spec,
});
const ids = (d) => new Set(d.violations.map((v) => v.policy_id));

test("tool name", () => assert.equal(TOOL_NAME, "admitd"));

test("builtins loaded (>=10)", () => {
  const pols = builtinPolicies();
  assert.ok(pols.length >= 10);
  assert.ok(pols.some((p) => p.id === "ADMITD-PRIV-001"));
});

test("privileged denied", () => {
  const d = evaluateObject(pod({ containers: [{ name: "c", image: "x:1.0", securityContext: { privileged: true } }] }), builtinPolicies());
  assert.equal(d.allowed, false);
  assert.ok(ids(d).has("ADMITD-PRIV-001"));
});

test("host namespaces denied", () => {
  const d = evaluateObject(pod({ hostNetwork: true, hostPID: true, containers: [{ name: "c", image: "x:1.0" }] }), builtinPolicies());
  assert.ok(ids(d).has("ADMITD-HOSTNS-003"));
});

test("hostPath volume denied", () => {
  const d = evaluateObject(pod({ volumes: [{ name: "h", hostPath: { path: "/" } }], containers: [{ name: "c", image: "x:1.0" }] }), builtinPolicies());
  assert.ok(ids(d).has("ADMITD-HOSTPATH-004"));
});

test(":latest tag denied", () => {
  const d = evaluateObject(pod({ containers: [{ name: "c", image: "nginx:latest" }] }), builtinPolicies());
  assert.ok(ids(d).has("ADMITD-LATEST-008"));
});

test("untagged image denied", () => {
  const d = evaluateObject(pod({ containers: [{ name: "c", image: "redis" }] }), builtinPolicies());
  assert.ok(ids(d).has("ADMITD-LATEST-008"));
});

test("digest-pinned image ok", () => {
  const d = evaluateObject(pod({ containers: [{ name: "c", image: "registry.internal/a@sha256:" + "a".repeat(64) }] }), builtinPolicies());
  assert.ok(!ids(d).has("ADMITD-LATEST-008"));
});

test("fully hardened pod allowed", () => {
  const d = evaluateObject(pod({
    containers: [{
      name: "c", image: "registry.internal/a:1.0",
      securityContext: {
        privileged: false, allowPrivilegeEscalation: false,
        runAsNonRoot: true, readOnlyRootFilesystem: true,
        seccompProfile: { type: "RuntimeDefault" },
        capabilities: { drop: ["ALL"] },
      },
      resources: { limits: { cpu: "100m", memory: "64Mi" } },
    }],
  }), builtinPolicies());
  assert.equal(d.allowed, true);
  assert.equal(d.violations.length, 0);
});

test("non-workload kind allowed", () => {
  const d = evaluateObject({ apiVersion: "v1", kind: "ConfigMap", metadata: { name: "cm" } }, builtinPolicies());
  assert.equal(d.allowed, true);
});

test("deployment nested podspec located", () => {
  const d = evaluateObject({
    kind: "Deployment", metadata: { name: "d" },
    spec: { template: { spec: { containers: [{ name: "c", image: "x:latest", securityContext: { privileged: true } }] } } },
  }, builtinPolicies());
  assert.equal(d.allowed, false);
  assert.ok(d.violations.some((v) => v.location.startsWith("/spec/template/spec/containers/0")));
});

test("cronjob deep podspec denied", () => {
  const d = evaluateObject({
    kind: "CronJob", metadata: { name: "cj" },
    spec: { jobTemplate: { spec: { template: { spec: { containers: [{ name: "c", image: "x:latest" }] } } } } },
  }, builtinPolicies());
  assert.equal(d.allowed, false);
});

test("splitImage: registry port not tag", () => {
  const [repo, tag] = splitImage("registry.local:5000/team/app:1.2");
  assert.equal(repo, "registry.local:5000/team/app");
  assert.equal(tag, "1.2");
});

test("splitImage: untagged", () => {
  assert.equal(splitImage("redis")[1], "");
});

test("parse AdmissionReview unwraps", () => {
  const objs = parseObjects(JSON.stringify({
    kind: "AdmissionReview", request: { uid: "u", object: { kind: "Pod", metadata: { name: "p" }, spec: { containers: [] } } },
  }));
  assert.equal(objs.length, 1);
  assert.equal(objs[0].kind, "Pod");
});

test("parse List object", () => {
  const objs = parseObjects(JSON.stringify({
    kind: "List", items: [
      { kind: "Pod", metadata: { name: "a" }, spec: { containers: [] } },
      { kind: "Pod", metadata: { name: "b" }, spec: { containers: [] } },
    ],
  }));
  assert.equal(objs.length, 2);
});

test("evaluateText aggregate report", () => {
  const report = evaluateText(JSON.stringify(pod({ containers: [{ name: "c", image: "x:latest", securityContext: { privileged: true } }] })));
  assert.equal(report.tool, "admitd");
  assert.equal(report.allowed, false);
  assert.ok(report.total_violations > 0);
  assert.equal(report.objects_denied, 1);
});

test("require_registry custom policy", () => {
  const pol = {
    id: "ADMITD-REG-1", title: "registry", severity: "high", control: "", action: "deny",
    rules: [{ require_registry: { allowed: ["registry.internal/"] } }],
  };
  const d = evaluateObject(pod({ containers: [{ name: "c", image: "docker.io/redis:7" }] }), [pol]);
  assert.equal(d.allowed, false);
  assert.equal(d.violations[0].policy_id, "ADMITD-REG-1");
});
