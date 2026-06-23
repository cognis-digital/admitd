#!/usr/bin/env node
// admitd Node CLI — mirrors the primary `admitd eval` / `admitd policies`
// surface. Reads a JSON manifest / AdmissionReview from a file (or `-` for
// stdin), evaluates it against the built-in hardening library, and prints the
// JSON report. Exits 1 if any object is denied. Offline, zero dependencies.

import { readFileSync } from "node:fs";
import { TOOL_NAME, TOOL_VERSION, builtinPolicies, evaluateText } from "./admitd.mjs";

function readInput(path) {
  if (path === "-") return readFileSync(0, "utf8");
  return readFileSync(path, "utf8");
}

function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0) {
    process.stderr.write("usage: admitd <eval|policies|--version> [args]\n");
    return 2;
  }
  if (args[0] === "--version") {
    process.stdout.write(`${TOOL_NAME} ${TOOL_VERSION}\n`);
    return 0;
  }
  if (args[0] === "policies") {
    const pols = builtinPolicies().map((p) => ({
      id: p.id, title: p.title, severity: p.severity,
      control: p.control, action: p.action, rule_count: p.rules.length,
    }));
    process.stdout.write(JSON.stringify(
      { tool: TOOL_NAME, version: TOOL_VERSION, count: pols.length, policies: pols }, null, 2) + "\n");
    return 0;
  }
  if (args[0] === "eval") {
    if (args.length < 2) {
      process.stderr.write("usage: admitd eval <manifest|->\n");
      return 2;
    }
    let text;
    try {
      text = readInput(args[1]);
    } catch (e) {
      process.stderr.write(`error: ${e.message}\n`);
      return 2;
    }
    let report;
    try {
      report = evaluateText(text, args[1]);
    } catch (e) {
      process.stderr.write(`error: ${e.message}\n`);
      return 2;
    }
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    return report.allowed ? 0 : 1;
  }
  process.stderr.write(`unknown command: ${args[0]}\n`);
  return 2;
}

process.exit(main(process.argv));
