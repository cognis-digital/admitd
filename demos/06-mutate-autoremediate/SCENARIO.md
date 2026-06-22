# Demo 06 — Auto-remediate with a mutate policy (JSONPatch)

**Where this came from.** A `legacy-worker` Pod has no `securityContext` at all.
Rather than *reject* it (which blocks the deploy and pages someone), the platform
team would rather **fix it automatically** at admission time. A `mutate` policy
turns its `require_*` rules into a JSONPatch that the mutating webhook applies
before the object is persisted.

## Files

- `under-hardened-pod.yaml` — a Pod missing all security context.
- `policies/mutate-hardening.yaml` — an `action: mutate` policy that injects
  `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, and
  `capabilities.drop: [ALL]`.

## Run it

```bash
# See the JSONPatch admitd would apply (JSON output shows the patches[] array):
python -m admitd eval demos/06-mutate-autoremediate/under-hardened-pod.yaml \
  --policies demos/06-mutate-autoremediate/policies/mutate-hardening.yaml \
  --no-builtin --format json
```

## What to expect

- The Pod is reported **allowed** (a mutate policy does not deny) with a
  populated `patches` array — `add` ops that build the `securityContext`,
  set the two booleans, and add the dropped-capabilities list.
- In a live cluster, `admitd serve --mutate` returns these as a base64
  JSONPatch in the `AdmissionReview` response, so the API server rewrites the
  object on the way in.

## How to act

Run the mutate policy in your `MutatingWebhookConfiguration` so under-hardened
workloads are repaired transparently, and keep the strict `deny` built-ins in the
`ValidatingWebhookConfiguration` as the backstop. Always review which fields you
auto-mutate — silently flipping `runAsNonRoot` can break images that truly need
a specific UID.
