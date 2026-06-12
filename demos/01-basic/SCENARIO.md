# Demo 01 — Gating an insecure Pod vs. a hardened Pod

This scenario runs `admitd` against two Pod manifests and one `AdmissionReview`.

## Run it

```bash
# An insecure Pod — should be DENIED (nonzero exit), one violation per failed control:
python -m admitd eval demos/01-basic/insecure-pod.yaml

# A fully hardened Pod — should be ALLOWED (exit 0), zero violations:
python -m admitd eval demos/01-basic/hardened-pod.yaml

# A real AdmissionReview wrapper — admitd unwraps request.object and evaluates it:
python -m admitd eval demos/01-basic/admissionreview.json --format json
```

## What `insecure-pod.yaml` should catch

| Control | Issue | Severity |
|---------|-------|----------|
| `ADMITD-PRIV-001` | container runs `privileged: true` | critical |
| `ADMITD-PRIVESC-002` | `allowPrivilegeEscalation: true` | high |
| `ADMITD-HOSTNS-003` | `hostNetwork` + `hostPID` enabled | high |
| `ADMITD-HOSTPATH-004` | mounts a `hostPath` volume (host root!) | high |
| `ADMITD-NONROOT-005` | does not require `runAsNonRoot` | high |
| `ADMITD-ROFS-006` | root filesystem is writable | medium |
| `ADMITD-DROPCAPS-007` | does not drop `ALL` capabilities | medium |
| `ADMITD-LATEST-008` | uses `nginx:latest` (mutable tag) | medium |
| `ADMITD-SECCOMP-010` | no seccomp profile | medium |
| `ADMITD-LIMITS-009` | no CPU / memory limits | low |

Because deny-action violations are present, the process exits non-zero — failing
any CI gate that wraps it. `hardened-pod.yaml` clears every control and is allowed.
