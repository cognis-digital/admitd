# Demo 08 — StatefulSet: tuning the gate severity

**Where this came from.** A Postgres `StatefulSet` (`orders-db`) is hardened on
every security control — non-root, read-only root FS, ALL caps dropped,
RuntimeDefault seccomp, no privilege escalation — but the DBA deliberately left
**resource limits** off while sizing the workload. The only finding is the
`low`-severity `ADMITD-LIMITS-009`.

This demo shows how to use `--fail-on` to set the CI gate threshold so a low-risk
advisory doesn't block a deploy, while a real security regression still does.

## Run it

```bash
# Default gate: any deny-action violation fails -> this DENIES on the LOW finding.
python -m admitd eval demos/08-statefulset-database/postgres.yaml

# Severity-gated CI: only fail on high+ . The low limits finding is reported
# but no longer blocks the pipeline -> exit 0.
python -m admitd eval demos/08-statefulset-database/postgres.yaml --fail-on high
```

## What to expect

- Default run: 1 object, **DENIED**, exit `1`, single finding `ADMITD-LIMITS-009`.
- `--fail-on high`: the same finding is printed, but the process exits `0`
  because nothing at `high` or above fired.

## How to act

Pick a gate threshold that matches your risk posture: `--fail-on critical` for a
permissive early-adoption rollout, tightening to `high` / `medium` over time. Then
fix the underlying issue — set `resources.limits` once the DB's steady-state
footprint is known — so you can drop the threshold back to the strict default.
