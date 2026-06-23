# admitd — language ports

The reference implementation of `admitd` is the Python package at the repo
root. These are **faithful, dependency-free ports** of the core CLI surface so
the same CIS / NSA-CISA hardening verdicts are available wherever your CI or
admission tooling already runs — no Python required.

Each port mirrors the primary commands:

| Command | Behavior |
|---------|----------|
| `admitd eval <manifest\|->` | evaluate a JSON manifest / k8s `List` / `AdmissionReview` (file or stdin) against the built-in hardening library; print the JSON report; exit `1` if any object is denied |
| `admitd policies` | list the built-in policy library as JSON |
| `admitd --version` | print `admitd <version>` |

All ports are **offline and deterministic**: they perform no network access of
any kind, read only from the path you pass (or stdin), and implement the exact
same ten built-in policies and rule verbs (`forbid_field`, `require_field`,
`forbid_pod_field`, `require_pod_field`, `forbid_image_tag`, `require_registry`,
`require_drop_caps`, `forbid_volume_type`, `require_resource_limits`) as the
Python engine. The JSON report shape (`tool`, `version`, `objects_evaluated`,
`objects_denied`, `total_violations`, `allowed`, `decisions[]`) matches
`admitd eval --format json`.

> The ports cover the **validate** path (eval / list policies). The full webhook
> server, `mutate` JSONPatch synthesis, SARIF / JUnit emitters, MCP server, and
> opt-in policy drafting remain Python-only — use the reference implementation
> for those surfaces.

## Go (`ports/go`)

```bash
cd ports/go
go test ./...                         # run the unit tests
go run . eval ../../demos/01-basic/admissionreview.json
go run . policies
echo '{"kind":"Pod","metadata":{"name":"p"},"spec":{"containers":[{"name":"c","image":"nginx:latest"}]}}' | go run . eval -
```

Standard library only (`encoding/json`); `go.mod` declares no dependencies.

## Node / TypeScript (`ports/node`)

```bash
cd ports/node
node --test                           # run the test suite (node:test)
node src/cli.mjs eval ../../demos/01-basic/admissionreview.json
node src/cli.mjs policies
```

Pure ES modules with JSDoc types (usable directly from TypeScript via
`allowJs`/`checkJs`); zero runtime dependencies. Requires Node ≥ 18.

## Rust (`ports/rust`)

```bash
cd ports/rust
cargo test                            # run the unit tests
cargo run --quiet -- eval ../../demos/01-basic/admissionreview.json
cargo run --quiet -- policies
```

Dependency-free (no serde): the engine ships with a small standard-library JSON
reader/writer in `src/json.rs`.

## CI

The [`.github/workflows/ports.yml`](../.github/workflows/ports.yml) workflow
builds and tests all three ports on every push and pull request, so each port is
verified on real toolchains even if you don't have Go / Rust installed locally.
