# admitd — Kubernetes policy-as-code admission engine

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ops`

[![CI](https://github.com/cognis-digital/admitd/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/admitd/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**Declarative allow / deny / mutate for Kubernetes admission — with a built-in library of CIS / NSA-CISA hardening policies.**

`admitd` evaluates a Kubernetes object (a `Pod`, `Deployment`, `DaemonSet`, …) or a full `AdmissionReview` against a set of declarative policies and returns an **allow**, **deny**, or **mutate** (JSONPatch) decision with a human-readable reason for every violation. Use it two ways:

- **In CI** — `admitd eval manifests/ ` fails your pipeline when a manifest breaks policy, with SARIF output for code-scanning.
- **In-cluster** — `admitd serve` is a stdlib HTTPS `ValidatingWebhookConfiguration` / `MutatingWebhookConfiguration` backend.

Standard library only. No agent, no CRDs to install, no third-party engine — a single self-hostable Python package.

## Usage — step by step

1. **Install** from source (Python 3.9+):
   ```bash
   pip install .
   ```
2. **Evaluate** a manifest or AdmissionReview against the built-in policies:
   ```bash
   admitd eval deployment.yaml
   ```
3. **List** the active policies (built-in + any loaded from a directory):
   ```bash
   admitd policies --policies ./policies --format json
   ```
4. **Use the output**: emit SARIF or JSON for code-scanning dashboards:
   ```bash
   admitd eval manifests/ --policies ./policies --format sarif --out admitd.sarif
   ```
5. **Gate in CI / serve as a webhook** — fail on findings, or run the live admission webhook:
   ```bash
   admitd eval manifests/ --format json --fail-on high
   admitd serve --port 8443 --tls-cert tls.crt --tls-key tls.key --mutate
   ```
   Also: `admitd draft "<rule>"` (opt-in AI policy draft) and `admitd mcp`.

## Why another admission tool

- **One artifact, two surfaces.** The same policies gate CI *and* live admission — no drift between "what the linter checks" and "what the cluster enforces."
- **Readable verdicts.** Every deny carries the offending JSON path, the mapped hardening control, and a concrete fix.
- **Hardening out of the box.** Ten built-in policies re-express widely published Kubernetes hardening guidance (CIS Benchmark, NSA/CISA Kubernetes Hardening Guidance).
- **Stdlib, scriptable, auditable.** No pip dependencies; the whole engine is plain Python you can read.

<!-- cognis:domains:start -->
## Domains

**Primary domain:** Cyber & Security  ·  **JTF MERIDIAN division:** NULLBYTE · SPECTER

**Topics:** `cognis` `security` `infosec` `cybersecurity` `blue-team` `kubernetes`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

## Install

```bash
pip install -e ".[dev]"        # from this repo
# or just run it in place:
python -m admitd --version
```

## Quick start

```bash
# Evaluate a manifest in CI (nonzero exit on deny):
python -m admitd eval demos/01-basic/insecure-pod.yaml          # -> DENY, exit 1
python -m admitd eval demos/01-basic/hardened-pod.yaml          # -> ALLOW, exit 0

# Machine-readable + SARIF for code-scanning:
python -m admitd eval manifests/ --format json
python -m admitd eval manifests/ --format sarif --out admitd.sarif --fail-on high

# List the built-in + loaded policies:
python -m admitd policies

# Run the admission webhook (HTTPS for a real cluster):
python -m admitd serve --tls-cert tls.crt --tls-key tls.key --port 8443 --mutate

# Expose as a local MCP server (Cognis.Studio / Claude Desktop / Cursor):
python -m admitd mcp
```

## The policy language

A policy is a small declarative document (JSON or YAML-subset):

```yaml
id: ADMITD-PRIV-001
title: Deny privileged containers
severity: critical
control: NSA-CISA K8s Hardening / CIS 5.2.1
action: deny            # deny | warn | mutate
match:
  kinds: [Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob]
rules:
  - forbid_field: {path: securityContext.privileged, equals: true}
```

Load your own with `--policies <dir-or-file>`; combine with or replace the built-ins via `--no-builtin`.

### Rule verbs

| Verb | Fires when… |
|------|-------------|
| `forbid_field` | any container sets `path` (optionally `==` a value) |
| `require_field` | any container is missing `path` (or it `!=` a value) |
| `forbid_pod_field` / `require_pod_field` | same, against the PodSpec |
| `forbid_image_tag` | an image uses a forbidden / implicit (`:latest`) tag |
| `require_registry` | an image is not from an allowed registry prefix |
| `require_drop_caps` | a container does not drop the listed Linux capabilities |
| `forbid_volume_type` | the PodSpec mounts a forbidden volume type (e.g. `hostPath`) |
| `require_resource_limits` | a container is missing CPU / memory limits |

A `mutate` policy turns its `require_*` rules into a JSONPatch so the webhook can auto-remediate (e.g. inject `runAsNonRoot: true`, `capabilities.drop: [ALL]`).

## Built-in hardening library

| Policy | Severity | Maps to |
|--------|----------|---------|
| `ADMITD-PRIV-001` | critical | deny privileged containers |
| `ADMITD-PRIVESC-002` | high | deny privilege escalation |
| `ADMITD-HOSTNS-003` | high | deny hostNetwork / hostPID / hostIPC |
| `ADMITD-HOSTPATH-004` | high | deny hostPath volumes |
| `ADMITD-NONROOT-005` | high | require `runAsNonRoot` |
| `ADMITD-ROFS-006` | medium | require read-only root filesystem |
| `ADMITD-DROPCAPS-007` | medium | require dropping `ALL` capabilities |
| `ADMITD-LATEST-008` | medium | deny `:latest` / untagged images |
| `ADMITD-LIMITS-009` | low | require CPU + memory limits |
| `ADMITD-SECCOMP-010` | medium | require a seccomp profile |

These are original re-expressions of public Kubernetes hardening concepts (CIS Kubernetes Benchmark, NSA/CISA Kubernetes Hardening Guidance). No third-party policy text is reproduced.

## Output formats

- **Table** (default) — human-readable per-object verdicts.
- **JSON** — machine-readable decisions for pipelines.
- **SARIF** — drops into GitHub code-scanning / IDE problem panes.
- **JUnit XML** (`--format junit`) — one `<testcase>` per object, one `<failure>`
  per broken control, so findings surface in the CI test-report pane of GitLab,
  Jenkins, Azure DevOps, CircleCI, or Buildkite alongside your unit tests:
  ```bash
  python -m admitd eval manifests/ --format junit --out admitd-junit.xml
  ```

## Demo scenarios

The [`demos/`](demos) directory holds runnable, real-use-case scenarios — each a
manifest (or `AdmissionReview` / custom policy) plus a `SCENARIO.md` explaining
where the data came from, what to expect, and how to act:

| Demo | Scenario | Shows |
|------|----------|-------|
| [`01-basic`](demos/01-basic) | insecure vs. hardened Pod | deny/allow basics, AdmissionReview |
| [`02-deployment-multidoc`](demos/02-deployment-multidoc) | multi-doc bundle, forgotten sidecar | every container is checked |
| [`03-cronjob-batch`](demos/03-cronjob-batch) | nightly CronJob | deep nested PodSpec + untagged image |
| [`04-daemonset-node-agent`](demos/04-daemonset-node-agent) | log collector | legitimate host access → exception workflow |
| [`05-custom-registry-policy`](demos/05-custom-registry-policy) | trusted-registry allow-list | authoring your own policy |
| [`06-mutate-autoremediate`](demos/06-mutate-autoremediate) | under-hardened Pod | `mutate` policy → JSONPatch repair |
| [`07-admissionreview-deny`](demos/07-admissionreview-deny) | node-shell escape attempt | live AdmissionReview, webhook deny |
| [`08-statefulset-database`](demos/08-statefulset-database) | Postgres StatefulSet | `--fail-on` severity gating |
| [`09-warn-vs-deny-gate`](demos/09-warn-vs-deny-gate) | FinOps cost-center label | `warn` action vs. the CI gate |
| [`10-helm-rendered-bundle`](demos/10-helm-rendered-bundle) | `helm template` output | gating a `List` + JUnit report for CI |

## As an admission webhook

`admitd serve` answers `POST /validate` and (with `--mutate`) `POST /mutate` with a standard `AdmissionReview` response — `allowed`, a 403 `status.message` listing the denying policies, and a base64 JSONPatch for mutations. Point a `ValidatingWebhookConfiguration` at it; TLS is required by the API server, so pass `--tls-cert`/`--tls-key`.

Smoke-test without a cluster:

```bash
python -m admitd serve --self-test     # binds localhost, posts a privileged Pod, asserts deny
```

## Opt-in AI policy drafting (off by default)

`admitd draft "deny any pod that mounts the docker socket"` can draft a new policy from a plain-English rule using the Cognis shared AI backend. It is **off by default** and talks only to a **local** fleet endpoint you configure (`COGNIS_AI_BACKEND` / `COGNIS_AI_ENDPOINT`) — nothing leaves your machine. The draft is always validated through the policy parser before it is printed, so a malformed suggestion can never become an executable policy. Review every draft before use.

## How it fits the Cognis Neural Suite

`admitd` is one tool in the [Cognis Neural Suite](https://github.com/cognis-digital). Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents can call them as scoped capabilities.

## Architecture & roadmap

- Design notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Planned work: [`ROADMAP.md`](ROADMAP.md)

## Contributing

PRs, new policies, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Interoperability

`admitd` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `admitd`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is security-governance software. Use it only against clusters, manifests, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
