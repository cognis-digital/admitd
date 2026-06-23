//! admitd Rust CLI — mirrors the primary `admitd eval` / `admitd policies`
//! surface. Reads a JSON manifest / AdmissionReview from a file (or `-` for
//! stdin), evaluates it against the built-in hardening library, and prints the
//! JSON report. Exits 1 if any object is denied. Offline, dependency-free.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::exit;

use admitd::json::{self, Json};
use admitd::{builtin_policies, evaluate_text, TOOL_NAME, TOOL_VERSION};

fn read_input(path: &str) -> std::io::Result<String> {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(path)
    }
}

fn run_policies() -> i32 {
    let pols = builtin_policies();
    let rows: Vec<Json> = pols
        .iter()
        .map(|p| {
            let mut m = BTreeMap::new();
            m.insert("id".into(), Json::Str(p.id.clone()));
            m.insert("title".into(), Json::Str(p.title.clone()));
            m.insert("severity".into(), Json::Str(p.severity.clone()));
            m.insert("control".into(), Json::Str(p.control.clone()));
            m.insert("action".into(), Json::Str(p.action.clone()));
            m.insert("rule_count".into(), Json::Num(p.rules.len() as f64));
            Json::Obj(m)
        })
        .collect();
    let mut out = BTreeMap::new();
    out.insert("tool".into(), Json::Str(TOOL_NAME.into()));
    out.insert("version".into(), Json::Str(TOOL_VERSION.into()));
    out.insert("count".into(), Json::Num(pols.len() as f64));
    out.insert("policies".into(), Json::Arr(rows));
    println!("{}", json::to_pretty(&Json::Obj(out)));
    0
}

fn run_eval(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: admitd eval <manifest|->");
        return 2;
    }
    let text = match read_input(&args[0]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {}", e);
            return 2;
        }
    };
    let report = match evaluate_text(&text, &args[0]) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {}", e);
            return 2;
        }
    };
    println!("{}", json::to_pretty(&report));
    match report.get("allowed") {
        Some(Json::Bool(true)) => 0,
        _ => 1,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: admitd <eval|policies|--version> [args]");
        exit(2);
    }
    let code = match args[0].as_str() {
        "--version" => {
            println!("{} {}", TOOL_NAME, TOOL_VERSION);
            0
        }
        "eval" => run_eval(&args[1..]),
        "policies" => run_policies(),
        other => {
            eprintln!("unknown command: {}", other);
            2
        }
    };
    exit(code);
}
