# Demo 02 — Multi-doc bundle: the forgotten sidecar

**Where this came from.** A platform team ships `payments-api` as a single
`kubectl apply -f app-bundle.yaml` with three documents in one file: the
`Deployment`, its `Service`, and a default-deny `NetworkPolicy`. The main `api`
container was hardened during review, but a `metrics-sidecar` was added later and
nobody re-ran the hardening checklist against it.

This is the most common real failure mode: **one container in a workload is
hardened, a second one isn't.** admitd evaluates *every* container (including
init / sidecar / ephemeral) in the pod template, so the sidecar can't hide.

## Run it

```bash
python -m admitd eval demos/02-deployment-multidoc/app-bundle.yaml
```

## What to expect

- 3 objects evaluated. The `Service` and `NetworkPolicy` have no PodSpec, so they
  are **allowed** (nothing to check).
- The `Deployment` is **DENIED** — but only on the `metrics-sidecar`:
  `ADMITD-NONROOT-005`, `ADMITD-ROFS-006`, `ADMITD-DROPCAPS-007`,
  `ADMITD-SECCOMP-010`. The `api` container raises nothing.
- Exit code `1` → fails the CI gate.

## How to act

Copy the `securityContext` block from `api` onto `metrics-sidecar` (or factor it
into a shared template). Re-run; the Deployment goes green. The `at:` JSON path
on each finding (`/spec/template/spec/containers/1/...`) points straight at the
offending container index.
