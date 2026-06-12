# admitd — Roadmap

> Kubernetes policy-as-code admission engine — declarative allow/deny/mutate.

## Now (v0.1.x)
- Declarative policy language (JSON + YAML-subset) with allow / deny / mutate.
- Built-in hardening library mapped to public CIS / NSA-CISA Kubernetes guidance.
- `eval` CLI with table / JSON / SARIF output and a `--fail-on` CI gate.
- Stdlib HTTPS AdmissionReview webhook (`serve`) with validate + mutate (JSONPatch).
- MCP stdio server exposing `eval` + `list_policies`.
- Opt-in, local-only AI policy drafting (`draft`), off by default.

## Next (v0.2)
- Policy parameters / variables and reusable rule libraries.
- More rule verbs: label/annotation requirements, image-signature attestation hooks.
- Namespace-scoped policy selectors and exemptions.
- Map each built-in policy to specific CIS benchmark item numbers.

## Later (v1.0)
- A stable plugin API for custom rule verbs.
- Performance pass, PyPI packaging, and a Pro tier (see `licensing@cognis.digital`).

Want something prioritized? Open an issue or a PR — see [CONTRIBUTING.md](CONTRIBUTING.md).
