# Demo 03 — CronJob: hardening lives several layers deep

**Where this came from.** An analytics team runs a nightly report as a
`CronJob`. CronJobs nest the PodSpec deeply — `spec.jobTemplate.spec.template.spec`
— so naive linters that only look at `spec.containers` miss them entirely. admitd
knows the PodSpec path for every workload kind, so the same controls apply.

The image is `reporting/builder` with **no tag**, which Kubernetes silently
resolves to a mutable `:latest`. The container also has no `securityContext`.

## Run it

```bash
python -m admitd eval demos/03-cronjob-batch/nightly-report.yaml
```

## What to expect

- 1 object, **DENIED**, exit `1`.
- Findings: `ADMITD-LATEST-008` (untagged image), `ADMITD-NONROOT-005`,
  `ADMITD-ROFS-006`, `ADMITD-DROPCAPS-007`, `ADMITD-SECCOMP-010`.
- Every `at:` path is rooted at `/spec/jobTemplate/spec/template/spec/...`,
  proving the deep PodSpec was reached.

## How to act

Pin the image to an immutable tag or digest (e.g.
`registry.internal/reporting/builder:2026.06.1`) and add the standard
`securityContext`. Batch workloads are a frequent blind spot — gate them in CI
the same way you gate long-running Deployments.
