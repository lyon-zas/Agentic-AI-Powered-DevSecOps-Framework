"""
Remediation evaluation for the paper: LLM fix quality (BLEU) and time to
remediate (MTTR) with a per-stage breakdown.

Cases are the vulnerable variants of the OWASP Juice Shop coding challenges
(data/static/codefixes/<challenge>_<n>.ts without "_correct"). For each case
the pipeline runs four timed stages (time.perf_counter):

  1. analysis       - analyze_vulnerability() on the scanner report, then a
                      Gemini call for root cause, CWE and severity
  2. fix            - Gemini generates the corrected snippet
  3. documentation  - generate_remediation_readme() from the remediation agent
  4. pr             - create_remediation_pr(dry_run=True): builds the branch,
                      title and body but makes no GitHub API call

MTTR for a case is the sum of the four stages. The generated fix is scored
with the repository's calculate_bleu_score() against the challenge's
*_correct snippet. As a reference point, the unchanged vulnerable snippet is
scored against the same reference (its BLEU shows how much overlap a
"no-change" answer already gets).

Usage:
  python evaluation/paper/run_remediation_timing.py --juice-shop DIR --out DIR \
      [--semgrep FILE] [--scan-cwd DIR] [--max-cases N]
"""
import argparse
import importlib.util
import json
import os
import random
import re
import statistics
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO))
import llm  # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Loaded by file path so the ADK agent package (__init__ imports google.adk)
# is not required to time the tools themselves.
tools = load_module("remediation_tools", REPO / "agents" / "remediation_agent" / "tools.py")
metrics = load_module("eval_metrics", REPO / "evaluation" / "metrics.py")

ANALYSIS_PROMPT = """You are the remediation agent of a DevSecOps pipeline. A scanner flagged
the file below (challenge "{challenge}", category "{category}").
Scanner report: {report}

Identify the vulnerability. Answer with JSON only:
{{"root_cause": "<one or two sentences>", "cwe": "CWE-<id>",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW", "affected_lines": [<line numbers>]}}

File {name}:
{code}
"""

FIX_PROMPT = """You are the remediation agent of a DevSecOps pipeline. Fix the vulnerability
described below with the smallest change that removes it while keeping the
code's behaviour. Return the complete corrected file.

Analysis: {analysis}

Answer with JSON only:
{{"fixed_code": "<the complete corrected file>",
  "fix_type": "<short name of the fix>",
  "explanation": "<why the fix works, one or two sentences>"}}

File {name}:
{code}
"""


def cases(js_root, max_cases, seed=42):
    import yaml
    root = Path(js_root)
    cats = {}
    chal = root / "data" / "static" / "challenges.yml"
    if chal.exists():
        for c in yaml.safe_load(chal.read_text()) or []:
            cats[c.get("key")] = c.get("category", "")
    d = root / "data" / "static" / "codefixes"
    correct = {p.name.split("_")[0]: p for p in d.iterdir() if "_correct" in p.name}
    out = []
    for p in sorted(d.iterdir()):
        if p.name.endswith(".info.yml") or "_correct" in p.name:
            continue
        key = p.name.split("_")[0]
        if key in correct:
            out.append({"challenge": key, "category": cats.get(key, ""), "file": p, "reference": correct[key]})
    if max_cases and len(out) > max_cases:
        out = sorted(random.Random(seed).sample(out, max_cases), key=lambda c: c["file"].name)
    return out


def load_findings(semgrep_file, scan_cwd):
    by_file = {}
    if semgrep_file and Path(semgrep_file).exists():
        for r in json.loads(Path(semgrep_file).read_text()).get("results", []):
            by_file.setdefault(os.path.realpath(os.path.join(scan_cwd, r["path"])), []).append(r)
    return by_file


def strip_fences(s):
    m = re.match(r"^\s*```[\w-]*\n(.*?)\n```\s*$", s, re.S)
    return m.group(1) if m else s


def run_case(c, findings):
    code = c["file"].read_text(errors="replace")
    reference = c["reference"].read_text(errors="replace")
    real = findings.get(os.path.realpath(c["file"]), [])
    report = real[0] if real else {
        "check_id": f"juice-shop.{c['challenge']}", "path": c["file"].name,
        "start": {"line": 1}, "end": {"line": len(code.splitlines())},
        "extra": {"severity": "ERROR", "message": c["category"] or c["challenge"], "metadata": {}},
    }
    t = {}

    # 1. analysis
    t0 = time.perf_counter()
    vuln = tools.analyze_vulnerability(report)
    local = time.perf_counter() - t0
    a, api, cached_a = llm.generate_json(
        ANALYSIS_PROMPT.format(challenge=c["challenge"], category=c["category"],
                               report=json.dumps(report.get("extra", {}).get("message", ""))[:500],
                               name=c["file"].name, code=code),
        mock={"root_cause": "MOCK", "cwe": "CWE-20", "severity": "HIGH", "affected_lines": []})
    t["analysis"] = local + api
    vuln.update({"description": a.get("root_cause", vuln["description"]),
                 "cwe": [a.get("cwe", "N/A")], "severity": a.get("severity", vuln["severity"]),
                 "file_path": c["file"].name})

    # 2. fix generation
    f, api, cached_f = llm.generate_json(
        FIX_PROMPT.format(analysis=json.dumps(a), name=c["file"].name, code=code),
        mock={"fixed_code": code, "fix_type": "MOCK", "explanation": "MOCK"})
    t0 = time.perf_counter()
    fixed = strip_fences(f.get("fixed_code", "") or "")
    fix = {"fix_type": f.get("fix_type", ""), "explanation": f.get("explanation", ""),
           "code_pattern": fixed[:1500], "recommendation": "Review the changes and run the test suite."}
    t["fix"] = api + (time.perf_counter() - t0)

    # 3. documentation
    t0 = time.perf_counter()
    readme = tools.generate_remediation_readme([vuln], [fix], "juice-shop")
    t["documentation"] = time.perf_counter() - t0

    # 4. pull request (dry run)
    t0 = time.perf_counter()
    pr = tools.create_remediation_pr("owner/juice-shop", [vuln], [fix], dry_run=True)
    t["pr"] = time.perf_counter() - t0

    bleu = metrics.calculate_bleu_score(fixed, reference)["bleu_score"]
    bleu_nochange = metrics.calculate_bleu_score(code, reference)["bleu_score"]
    return {
        "case": c["file"].name, "challenge": c["challenge"], "category": c["category"],
        "scanner_finding": bool(real), "stages_s": {k: round(v, 4) for k, v in t.items()},
        "mttr_s": round(sum(t.values()), 4), "bleu": bleu, "bleu_unchanged_baseline": bleu_nochange,
        "fixed_differs_from_input": fixed.strip() != code.strip(),
        "cwe": a.get("cwe"), "readme_chars": len(readme), "pr_ok": bool(pr.get("success")),
        "llm_cached": cached_a or cached_f,
    }


def summary(xs):
    xs = list(xs)
    return {"mean": round(statistics.mean(xs), 3), "sd": round(statistics.stdev(xs), 3) if len(xs) > 1 else 0.0,
            "median": round(statistics.median(xs), 3), "min": round(min(xs), 3), "max": round(max(xs), 3)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--juice-shop", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--semgrep")
    ap.add_argument("--scan-cwd", default=".")
    ap.add_argument("--max-cases", type=int, default=0)
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    findings = load_findings(a.semgrep, a.scan_cwd)
    rows = []
    cs = cases(a.juice_shop, a.max_cases)
    for i, c in enumerate(cs, 1):
        r = run_case(c, findings)
        rows.append(r)
        print(f"[{i}/{len(cs)}] {r['case']} mttr={r['mttr_s']:.2f}s bleu={r['bleu']:.4f}", flush=True)

    stages = ["analysis", "fix", "documentation", "pr"]
    mean_stage = {s: statistics.mean(r["stages_s"][s] for r in rows) for s in stages}
    res = {
        "mock": llm.MOCK, "model": llm.MODEL, "cases": len(rows),
        "mttr_s": summary(r["mttr_s"] for r in rows),
        "stage_mean_s": {s: round(v, 4) for s, v in mean_stage.items()},
        "stage_share_pct": {s: round(100 * v / sum(mean_stage.values()), 1) for s, v in mean_stage.items()},
        "bleu": summary(r["bleu"] for r in rows),
        "bleu_unchanged_baseline": summary(r["bleu_unchanged_baseline"] for r in rows),
        "fixes_that_changed_code_pct": round(100 * sum(r["fixed_differs_from_input"] for r in rows) / len(rows), 1),
        "cases_with_scanner_finding": sum(r["scanner_finding"] for r in rows),
        "cases_served_from_cache": sum(r["llm_cached"] for r in rows),
        "note": "PR stage is a dry run (no GitHub API latency). LLM latency for cached cases is the latency recorded when first called.",
    }
    (out / "remediation_cases.json").write_text(json.dumps(rows, indent=1))
    (out / "remediation_results.json").write_text(json.dumps(res, indent=1))
    md = to_markdown(res)
    (out / "remediation_results.md").write_text(md)
    print(md)


def to_markdown(r):
    L = []
    if r["mock"]:
        L.append("> **MOCK RUN: LLM answers are placeholders. Do not use these numbers.**\n")
    L.append(f"### Remediation results (model: {r['model']}, {r['cases']} cases)\n")
    m = r["mttr_s"]
    L.append(f"MTTR: mean {m['mean']} s, SD {m['sd']} s, median {m['median']} s (range {m['min']}-{m['max']} s)\n")
    L.append("| Stage | Mean time (s) | Share % |")
    L.append("|---|---|---|")
    for s, v in r["stage_mean_s"].items():
        L.append(f"| {s} | {v} | {r['stage_share_pct'][s]} |")
    b, b0 = r["bleu"], r["bleu_unchanged_baseline"]
    L.append(f"\nBLEU (LLM fix vs reference fix): mean {b['mean']}, SD {b['sd']}, median {b['median']}")
    L.append(f"BLEU (unchanged vulnerable code vs reference, baseline): mean {b0['mean']}, median {b0['median']}")
    L.append(f"Fixes that changed the code: {r['fixes_that_changed_code_pct']}%")
    L.append(f"Cases with a Semgrep finding: {r['cases_with_scanner_finding']}; served from cache: {r['cases_served_from_cache']}")
    L.append(f"\n_{r['note']}_")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
