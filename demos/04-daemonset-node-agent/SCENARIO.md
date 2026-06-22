# Demo 04 — Node agent: a legitimately privileged DaemonSet

**Where this came from.** A log collector runs as a `DaemonSet` on every node and
genuinely needs `hostNetwork` and a read-only `hostPath` mount of `/var/log` to do
its job. The container itself is otherwise fully hardened (non-root, read-only
root FS, drops ALL caps, RuntimeDefault seccomp).

This scenario shows the **expected-exception** workflow: admitd is correct to
flag `hostNetwork` and `hostPath`, and you handle it by *documenting an exception*
— not by silencing the engine globally.

## Run it

```bash
python -m admitd eval demos/04-daemonset-node-agent/log-collector.yaml
```

## What to expect

- 1 object, **DENIED**, exit `1`.
- Exactly two findings: `ADMITD-HOSTNS-003` (hostNetwork) and
  `ADMITD-HOSTPATH-004` (hostPath). No other control fires — the container is
  hardened.

## How to act — two legitimate paths

1. **Scope an exception policy** for this namespace/workload (e.g. run node
   agents under a policy set loaded with `--policies node-agents/ --no-builtin`
   that omits the two host-isolation rules), and keep the strict built-ins for
   tenant workloads.
2. **Tighten the request**: drop `hostNetwork` if the collector can scrape over
   the pod network, and mount the narrowest `hostPath` subtree possible
   (`readOnly: true`, which this manifest already does).

The point: admitd gives you the precise control IDs to reason about, instead of a
blanket allow/deny.
