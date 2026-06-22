# Demo 10 — Gating `helm template` output + a JUnit report for CI

**Where this came from.** A chart is rendered to a single stream and piped into a
CI gate — the canonical `helm template . | admitd eval -` workflow (here captured
as a `v1/List` JSON, the shape `helm template --output-dir` / `kubectl get -o
json` produce). The bundle has a clean `frontend` Deployment and a `db-migrate`
Job whose author marked it `privileged: true` "just to get the migration through."

This demo also exercises the new **`--format junit`** exporter, so admitd findings
land in the same test-report pane as your unit tests (GitLab, Jenkins, Azure
DevOps, CircleCI, Buildkite all ingest JUnit XML).

## Run it

```bash
# Human view: the List is flattened into its items and each is evaluated.
python -m admitd eval demos/10-helm-rendered-bundle/rendered.json

# Emit a JUnit report for the CI test-results pane:
python -m admitd eval demos/10-helm-rendered-bundle/rendered.json \
  --format junit --out admitd-junit.xml

# SARIF for GitHub code-scanning, for comparison:
python -m admitd eval demos/10-helm-rendered-bundle/rendered.json --format sarif
```

## What to expect

- 2 objects evaluated. `frontend` is **allowed**; `db-migrate` is **DENIED**
  (`ADMITD-PRIV-001` plus the missing-hardening controls). Exit `1`.
- The JUnit XML has `tests="2"` with one passing `<testcase>` (frontend) and one
  failing testcase carrying a `<failure>` per broken control.

## How to act

Wire the JUnit step into CI:

```yaml
# GitLab CI
admission_gate:
  script:
    - helm template charts/shop | python -m admitd eval - --format junit --out admitd-junit.xml
  artifacts:
    reports:
      junit: admitd-junit.xml
```

Then drop `privileged: true` from the migration Job and give it the standard
`securityContext`; a migration almost never needs host privileges.
