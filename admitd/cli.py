"""Command-line interface for admitd."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from admitd import TOOL_NAME, TOOL_VERSION
from admitd.core import (
    Decision,
    PolicyError,
    SEVERITY_ORDER,
    all_policies,
    decisions_to_dict,
    evaluate_file,
    evaluate_object,
    load_manifest_file,
    to_junit,
    to_sarif,
)

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def _render_decision(d: Decision) -> str:
    lines: List[str] = []
    verdict = "ALLOW" if d.allowed else "DENY"
    head = f"{d.kind}/{d.name}"
    if d.namespace:
        head += f" (ns: {d.namespace})"
    lines.append(f"[{verdict}] {head}")
    if d.source:
        lines.append(f"        source: {d.source}")
    for v in d.violations:
        label = _SEV_LABEL.get(v.severity, v.severity.upper())
        marker = {"deny": "x", "warn": "!", "mutate": "~"}.get(v.action, "-")
        lines.append(f"  {marker} [{label}] {v.policy_id}  {v.title}")
        lines.append(f"        {v.message}")
        if v.control:
            lines.append(f"        control: {v.control}")
        if v.location:
            lines.append(f"        at: {v.location}")
        if v.remediation:
            lines.append(f"        fix: {v.remediation}")
    for p in d.patches:
        lines.append(f"  ~ [MUTATE] {p.policy_id}  {p.op} {p.path} = {json.dumps(p.value)}")
    if not d.violations and not d.patches:
        lines.append("        no policy violations")
    return "\n".join(lines)


def _render_table(decisions: List[Decision]) -> str:
    if not decisions:
        return "No Kubernetes objects found to evaluate."
    blocks = [f"{TOOL_NAME} eval — {len(decisions)} object(s)", "=" * 68]
    blocks.extend(_render_decision(d) for d in decisions)
    denied = sum(1 for d in decisions if not d.allowed)
    total = sum(len(d.violations) for d in decisions)
    blocks.append("-" * 68)
    blocks.append(
        f"SUMMARY: {len(decisions)} object(s), {denied} denied, {total} violation(s)."
    )
    blocks.append("RESULT: " + ("DENY" if denied else "ALLOW"))
    return "\n".join(blocks)


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _fails_gate(decisions: List[Decision], fail_on: Optional[str]) -> bool:
    """A run "fails" (nonzero exit) per the gate policy.

    Default: any deny-action violation denies admission. With ``--fail-on`` the
    gate trips on any violation at/above the given severity, regardless of its
    action (so a ``warn`` policy can still gate CI when asked).
    """
    if not fail_on:
        return any(not d.allowed for d in decisions)
    threshold = SEVERITY_ORDER[fail_on]
    return any(
        SEVERITY_ORDER.get(v.severity, 99) <= threshold
        for d in decisions for v in d.violations
    )


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Kubernetes policy-as-code admission engine — declarative "
                    "allow/deny/mutate with built-in CIS / NSA-CISA hardening policies.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    ev = sub.add_parser("eval", help="Evaluate manifest(s) / AdmissionReview(s) against policies.")
    ev.add_argument("manifest", help="Path to a k8s manifest, JSON, or AdmissionReview.")
    ev.add_argument("--policies", help="Directory or file of extra policies to load.")
    ev.add_argument("--no-builtin", action="store_true",
                    help="Do not load the built-in hardening policy library.")
    ev.add_argument("--format", choices=("table", "json", "sarif", "junit"), default="table",
                    help="Output format (default: table). 'junit' emits a JUnit "
                         "XML report for CI test-report panes.")
    ev.add_argument("--out", help="Write output to this file instead of stdout.")
    ev.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                    help="Exit non-zero if a violation at/above this severity exists.")

    sv = sub.add_parser("serve", help="Run an HTTPS AdmissionReview webhook server.")
    sv.add_argument("--policies", help="Directory or file of extra policies to load.")
    sv.add_argument("--no-builtin", action="store_true",
                    help="Do not load the built-in hardening policy library.")
    sv.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0).")
    sv.add_argument("--port", type=int, default=8443, help="Listen port (default: 8443).")
    sv.add_argument("--tls-cert", help="Path to the TLS certificate (PEM).")
    sv.add_argument("--tls-key", help="Path to the TLS private key (PEM).")
    sv.add_argument("--mutate", action="store_true",
                    help="Apply mutate policies (return JSONPatch) as well as validate.")
    sv.add_argument("--self-test", action="store_true",
                    help="Bind, issue one local request, then shut down (smoke test).")

    pol = sub.add_parser("policies", help="List built-in + loaded policies.")
    pol.add_argument("--policies", help="Directory or file of extra policies to load.")
    pol.add_argument("--no-builtin", action="store_true",
                     help="Do not list the built-in hardening policy library.")
    pol.add_argument("--format", choices=("table", "json"), default="table",
                     help="Output format (default: table).")

    dr = sub.add_parser("draft", help="Draft a new policy from a plain-English rule (opt-in AI).")
    dr.add_argument("description", help="Plain-English description of the rule.")
    dr.add_argument("--id", help="Suggested policy id for the draft.")

    mcp = sub.add_parser("mcp", help="Run as an MCP server (stdio JSON-RPC).")
    mcp.add_argument("--host", default=None, help="Reserved; stdio transport only.")
    return p


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------

def _load(args) -> List:
    return all_policies(
        extra_dir=getattr(args, "policies", None),
        include_builtin=not getattr(args, "no_builtin", False),
    )


def _run_eval(args: argparse.Namespace) -> int:
    try:
        policies = _load(args)
    except (OSError, PolicyError) as exc:
        print(f"error loading policies: {exc}", file=sys.stderr)
        return 2
    try:
        decisions = evaluate_file(args.manifest, policies)
    except (OSError, PolicyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    fmt = args.format
    if fmt == "json":
        _emit(json.dumps(decisions_to_dict(decisions), indent=2), args.out)
    elif fmt == "sarif":
        _emit(json.dumps(to_sarif(decisions), indent=2), args.out)
    elif fmt == "junit":
        _emit(to_junit(decisions), args.out)
    else:
        _emit(_render_table(decisions), args.out)

    return 1 if _fails_gate(decisions, args.fail_on) else 0


def _run_policies(args: argparse.Namespace) -> int:
    try:
        policies = _load(args)
    except (OSError, PolicyError) as exc:
        print(f"error loading policies: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        payload = [{
            "id": p.id, "title": p.title, "severity": p.severity,
            "control": p.control, "action": p.action,
            "kinds": p.match_kinds, "source": p.source,
            "rule_count": len(p.rules),
        } for p in policies]
        print(json.dumps({"tool": TOOL_NAME, "version": TOOL_VERSION,
                          "count": len(policies), "policies": payload}, indent=2))
        return 0

    print(f"{TOOL_NAME} {TOOL_VERSION} — {len(policies)} policy(ies)")
    print("=" * 72)
    for p in policies:
        label = _SEV_LABEL.get(p.severity, p.severity.upper())
        origin = "builtin" if p.source == "<builtin>" else p.source
        print(f"[{label}] {p.id:<22} {p.action:<6} {p.title}")
        if p.control:
            print(f"            control: {p.control}")
        print(f"            rules: {len(p.rules)}  source: {origin}")
    return 0


def _run_draft(args: argparse.Namespace) -> int:
    from admitd import _ai
    if not _ai.is_enabled():
        print("AI backend is OFF (default). Enable it by pointing at a LOCAL "
              "fleet endpoint, e.g.:\n"
              "  export COGNIS_AI_BACKEND=uncensored-fleet\n"
              "  # or: export COGNIS_AI_ENDPOINT=http://127.0.0.1:8774/v1 "
              "COGNIS_AI_MODEL=<model>\n"
              "Then re-run `admitd draft \"...\"`. Nothing leaves your machine.",
              file=sys.stderr)
        return 3
    if not _ai.health():
        print("AI backend is configured but the endpoint is not responding.",
              file=sys.stderr)
        return 3
    draft = _ai.draft_policy(args.description, suggested_id=args.id)
    if draft is None:
        print("AI did not produce a valid policy draft. Try rephrasing the rule.",
              file=sys.stderr)
        return 1
    print(json.dumps(draft, indent=2))
    print("# Review this draft, save it to a policies dir, then run: "
          "admitd eval <manifest> --policies <dir>", file=sys.stderr)
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    from admitd.server import serve, self_test
    try:
        policies = _load(args)
    except (OSError, PolicyError) as exc:
        print(f"error loading policies: {exc}", file=sys.stderr)
        return 2
    if args.self_test:
        ok = self_test(policies, mutate=args.mutate)
        return 0 if ok else 1
    return serve(
        policies,
        host=args.host,
        port=args.port,
        tls_cert=args.tls_cert,
        tls_key=args.tls_key,
        mutate=args.mutate,
    )


def _run_mcp() -> int:
    from admitd.mcp_server import run_mcp_server
    run_mcp_server()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "eval":
        return _run_eval(args)
    if args.command == "policies":
        return _run_policies(args)
    if args.command == "draft":
        return _run_draft(args)
    if args.command == "serve":
        return _run_serve(args)
    if args.command == "mcp":
        return _run_mcp()
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
