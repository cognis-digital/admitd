# Demo 09 — warn vs. deny: advisory policies that don't block

**Where this came from.** A FinOps team wants every workload to carry a
`cost-center` nodeSelector for spend attribution — but they do **not** want to
break deploys over a missing label. They model it as an `action: warn` policy.
The `web` Deployment is fully security-hardened but has no `cost-center`, so it
should be *allowed with a warning*, not denied.

This demo shows the difference between a policy's *action* (deny / warn / mutate)
and the CI *gate* (`--fail-on`), and how to escalate an advisory into a blocker.

## Files

- `web.yaml` — a hardened Deployment with no cost-center nodeSelector.
- `policies/labels-warn.yaml` — `ACME-LABELS-WARN`, an `action: warn` policy.

## Run it

```bash
# Default: warn-action findings do NOT gate -> ALLOW, exit 0.
python -m admitd eval demos/09-warn-vs-deny-gate/web.yaml \
  --policies demos/09-warn-vs-deny-gate/policies

# Escalate: gate on any finding at/above 'low', regardless of action ->
# the warn now blocks the pipeline, exit 1.
python -m admitd eval demos/09-warn-vs-deny-gate/web.yaml \
  --policies demos/09-warn-vs-deny-gate/policies --fail-on low
```

## What to expect

- Default run: object **ALLOWED** (exit `0`), but the table prints the advisory
  finding with a `!` warn marker.
- `--fail-on low`: same finding, now exit `1` — useful once you're ready to make
  the convention mandatory.

## How to act

Roll new conventions out as `warn` policies first to measure the blast radius,
then either flip them to `action: deny` or start gating with `--fail-on` once the
fleet is clean. In a webhook, `warn` findings surface as Kubernetes admission
`warnings[]` — visible in `kubectl` output without blocking the apply.
