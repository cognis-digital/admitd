# Demo 07 — A live AdmissionReview: blocking a node-shell escape

**Where this came from.** This is a real-shaped `AdmissionReview` v1 request — the
exact JSON the Kubernetes API server `POST`s to a validating webhook. A service
account (`system:serviceaccount:tenant-x:deployer`) is trying to create a
`node-shell` DaemonSet in `kube-system` that is, in effect, a host-escape
toolkit: `privileged`, `allowPrivilegeEscalation`, `hostPID`, `hostNetwork`, and a
`hostPath` mount of `/`.

admitd unwraps `request.object` from the review and evaluates the embedded
DaemonSet, exactly as `admitd serve` does in-cluster.

## Run it

```bash
python -m admitd eval demos/07-admissionreview-deny/review-privileged-daemonset.json
# machine-readable:
python -m admitd eval demos/07-admissionreview-deny/review-privileged-daemonset.json --format json
```

## What to expect

- 1 object (kind `DaemonSet`, unwrapped from the review), **DENIED**, exit `1`.
- This trips essentially the whole library at once: `ADMITD-PRIV-001`,
  `ADMITD-PRIVESC-002`, `ADMITD-HOSTNS-003`, `ADMITD-HOSTPATH-004`,
  `ADMITD-NONROOT-005`, `ADMITD-ROFS-006`, `ADMITD-DROPCAPS-007`,
  `ADMITD-LATEST-008` (`alpine` is untagged), `ADMITD-SECCOMP-010`,
  `ADMITD-LIMITS-009`.

## How to act

In-cluster, `admitd serve` returns this as `allowed: false` with a 403
`status.message` listing the denying policies — the API server rejects the create
and the user sees why. Use this fixture to smoke-test your webhook wiring without
provisioning a privileged workload against a real node.
