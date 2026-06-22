# Demo 05 — Your own policy: enforce a trusted-registry allow-list

**Where this came from.** A workload (`cache`, a Redis Deployment) is perfectly
hardened against the built-in CIS / NSA-CISA controls — but it pulls
`docker.io/library/redis:7.2.4` straight from Docker Hub. Org supply-chain policy
says images must come from the internal mirror or the org's GHCR namespace.

This demo loads **only a custom policy** (`--no-builtin`) so you can see that a
single org rule fires on a workload the built-ins would happily allow.

## Files

- `deployment.yaml` — the workload under test.
- `policies/registry-allowlist.yaml` — a custom `require_registry` policy
  (`ACME-REGISTRY-001`) allowing only `registry.internal/` and
  `ghcr.io/acme-corp/`.

## Run it

```bash
# Custom policy only:
python -m admitd eval demos/05-custom-registry-policy/deployment.yaml \
  --policies demos/05-custom-registry-policy/policies --no-builtin

# Or layer it on top of the built-in hardening library (drop --no-builtin):
python -m admitd eval demos/05-custom-registry-policy/deployment.yaml \
  --policies demos/05-custom-registry-policy/policies
```

## What to expect

- 1 object, **DENIED**, exit `1`.
- A single finding: `ACME-REGISTRY-001` — image not from an allowed registry.
- The remediation text comes straight from the policy file, so your authors
  control the fix message.

## How to act

Mirror the image into an approved registry and reference it there
(`registry.internal/cache/redis:7.2.4`). This pattern — built-ins for baseline
hardening, custom policies for org-specific rules — is how teams extend admitd
without forking it.
