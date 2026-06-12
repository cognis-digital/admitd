# admitd — Architecture

`admitd` is a small, dependency-free policy engine with three front-ends over one core.

```
                    ┌────────────────────────────────────────────┐
                    │                admitd.core                  │
                    │                                              │
   manifest /  ───► │  parse_objects ──► evaluate_object ──► Decision
   AdmissionReview  │  (JSON + YAML-      (rule verbs over    (allow/deny
                    │   subset reader)     each PodSpec)        + JSONPatch)
                    │         ▲                  ▲                  │
                    │   builtin_policies()  load_policies_dir()     │
                    └─────────┼──────────────────┼─────────────────┘
                              │                  │
        ┌─────────────────────┼──────────────────┼─────────────────────┐
        │ cli.py (eval/policies)   server.py (HTTPS webhook)   mcp_server.py (stdio)
        └───────────────────────────────────────────────────────────────┘
                              │
                        _ai.py (opt-in, local-only policy drafting — OFF by default)
```

## Components

- **`core.py`** — the engine. Parses Kubernetes objects (JSON, a YAML-subset
  reader with no PyYAML dependency, k8s `List`, and `AdmissionReview` unwrapping),
  resolves the PodSpec for every container-bearing workload kind, and runs each
  policy's rules. Produces `Decision` objects (allow/deny + violations +
  JSONPatch). Also holds the built-in policy library, the SARIF serializer, and
  the AdmissionReview response builder.

- **`cli.py`** — `eval` (table / JSON / SARIF, `--fail-on` gate), `policies`,
  `draft` (AI), `serve`, and `mcp` subcommands.

- **`server.py`** — a `http.server` + `ssl` HTTPS webhook. `POST /validate`
  returns allow/deny; `POST /mutate` (with `--mutate`) returns a base64 JSONPatch.
  `self_test` binds localhost, posts a privileged Pod, and asserts the deny.

- **`mcp_server.py`** — newline-delimited JSON-RPC 2.0 over stdio exposing
  `eval` and `list_policies` as MCP tools. No SDK required.

- **`_ai.py`** + **`_ai_backend.py`** — the Cognis shared, env-driven,
  local-only AI client. Off by default; used solely to *draft* a policy from a
  plain-English description, which is then re-validated by the policy parser.

## Design choices

- **Standard library only.** No PyYAML, no web framework, no MCP SDK. The
  YAML-subset reader covers the mapping / block-sequence / scalar / inline-flow
  syntax real Kubernetes manifests use.
- **One policy set, two enforcement points.** CI `eval` and the in-cluster
  webhook share `evaluate_object`, so a manifest that passes CI passes admission.
- **JSON-pointer locations.** Every violation reports the exact path inside the
  object (e.g. `/spec/template/spec/containers/0/securityContext/privileged`),
  which doubles as the target path for mutation patches.
- **Deterministic by default.** The engine never reaches the network; the AI
  layer is strictly opt-in and only contacts a local endpoint.

## Clean-room statement

`admitd` is 100% original Cognis Digital work. It is inspired only by the public
*concept* of policy-as-code Kubernetes admission control and by openly published
hardening guidance (CIS Kubernetes Benchmark, NSA/CISA Kubernetes Hardening
Guidance). No third-party engine's source, policy text, naming, or branding is
copied, forked, or vendored.
