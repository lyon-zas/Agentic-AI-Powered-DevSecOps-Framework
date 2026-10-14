"""
Detection evaluation for the paper.

Scores three detectors against the labelled units in ground_truth.py:

  semgrep    - Semgrep alone (a unit is flagged when any security-category
               finding falls in its files). This is the scanner baseline.
  framework  - the framework's SAST agent: Gemini receives the unit's code
               together with Semgrep's findings and returns a verdict.
  llm_only   - ablation: Gemini receives the code only.

Reports, per benchmark and overall: TP, FN, FP, TN, defect-detection rate
(DDR = TP / (TP + FN)) with a Wilson 95% interval, precision, false-positive
rate and F1 where negatives exist, macro (unweighted) and pooled (weighted)
DDR, a CWE-matched DDR where the benchmark has CWE labels, and an exact
McNemar test comparing each LLM detector with Semgrep on the same units.

Usage:
  python evaluation/paper/run_detection.py --datasets DIR --semgrep DIR \
      --out DIR [--modes framework,llm_only] [--scan-cwd DIR]

DIR for --datasets holds dvwa/, juice-shop/, webgoat/. DIR for --semgrep holds
<dataset>.json, Semgrep's --json output for each benchmark.
"""
import argparse
import json
import math
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import llm  # noqa: E402
from ground_truth import all_units  # noqa: E402

DATASETS = ["webgoat", "dvwa", "juice-shop"]
MAX_CODE_CHARS = int(os.getenv("MAX_CODE_CHARS", "120000"))

PROMPT = """You are the SAST agent of a DevSecOps pipeline. Decide whether the code
below contains at least one exploitable security vulnerability.
{findings_block}
Answer with JSON only:
{{"vulnerable": true or false,
  "cwe": ["CWE-<id>", ...],
  "lines": [<line numbers>],
  "explanation": "<one or two sentences>"}}

Code ({n_files} file(s)):
{code}
"""


def norm_cwe(x):
    """'CWE-89: Improper ...' -> 'CWE-89'."""
    x = str(x).strip().upper()
    if not x.startswith("CWE-"):
        x = "CWE-" + x.split("-")[-1]
    return x.split(":")[0].split(" ")[0]


def load_semgrep(semgrep_dir, scan_cwd):
    by_file = defaultdict(list)
    for ds in DATASETS:
        f = Path(semgrep_dir) / f"{ds}.json"
        if not f.exists():
            continue
        for r in json.loads(f.read_text()).get("results", []):
            md = r.get("extra", {}).get("metadata", {})
            if md.get("category") != "security":
                continue
            cwe = md.get("cwe", [])
            cwe = [cwe] if isinstance(cwe, str) else cwe
            by_file[os.path.realpath(os.path.join(scan_cwd, r["path"]))].append({
                "rule": r.get("check_id", ""),
                "line": r.get("start", {}).get("line"),
                "message": r.get("extra", {}).get("message", "")[:300],
                "cwe": [norm_cwe(c) for c in cwe],
            })
    return by_file


def unit_findings(u, by_file):
    out = []
    for f in u["files"]:
        for x in by_file.get(os.path.realpath(f), []):
            out.append({**x, "file": os.path.basename(f)})
    return out


def code_of(u):
    parts, total = [], 0
    for f in u["files"]:
        txt = Path(f).read_text(errors="replace")
        numbered = "\n".join(f"{i + 1:4d} {line}" for i, line in enumerate(txt.splitlines()))
        block = f"--- {os.path.basename(f)} ---\n{numbered}\n"
        if total + len(block) > MAX_CODE_CHARS:
            parts.append(f"--- (remaining files omitted: {MAX_CODE_CHARS} character budget) ---")
            break
        parts.append(block)
        total += len(block)
    return "".join(parts)


def ask(u, findings, with_scanner):
    if with_scanner:
        if findings:
            lines = "\n".join(f"- {x['file']}:{x['line']} {x['rule']} ({', '.join(x['cwe'])}): {x['message']}"
                              for x in findings[:50])
            fb = f"\nSemgrep reported these findings (they may include false positives):\n{lines}\n"
        else:
            fb = "\nSemgrep reported no findings for this code (it may have missed issues).\n"
    else:
        fb = ""
    prompt = PROMPT.format(findings_block=fb, n_files=len(u["files"]), code=code_of(u))
    mock = {"vulnerable": bool(findings), "cwe": sorted({c for x in findings for c in x["cwe"]}),
            "lines": [], "explanation": "MOCK"}
    resp, secs, cached = llm.generate_json(prompt, mock=mock)
    v = resp.get("vulnerable")
    if isinstance(v, str):
        v = v.strip().lower() == "true"
    return {"vulnerable": bool(v), "cwe": [norm_cwe(c) for c in resp.get("cwe", []) or []],
            "explanation": resp.get("explanation", ""), "seconds": secs, "cached": cached,
            "unparsed": "_unparsed" in resp}


def wilson(k, n, z=1.96):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * (c - h), 2), round(100 * (c + h), 2))


def mcnemar_exact(b, c):
    """Two-sided exact McNemar p-value. b: only A correct, c: only B correct."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    p = 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, p)


def score(rows, det, cwe_match=False):
    tp = fn = fp = tn = 0
    for r in rows:
        pred = r[det]["vulnerable"]
        if cwe_match and r["label"] == 1:
            pred = pred and bool(set(r[det]["cwe"]) & set(r["cwe"]))
        if r["label"] == 1:
            tp += pred
            fn += not pred
        else:
            fp += pred
            tn += not pred
    pos, neg = tp + fn, fp + tn
    prec = tp / (tp + fp) if tp + fp else None
    ddr = tp / pos if pos else None
    return {
        "units": len(rows), "positives": pos, "negatives": neg,
        "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "DDR": round(100 * ddr, 2) if ddr is not None else None,
        "DDR_95CI": wilson(tp, pos),
        "precision": round(100 * prec, 2) if prec is not None and neg else None,
        "FPR": round(100 * fp / neg, 2) if neg else None,
        "F1": round(2 * prec * ddr / (prec + ddr), 4) if neg and prec and ddr else None,
    }


def compare(rows, a, b):
    """McNemar on correctness of detector a vs detector b over the same units."""
    only_a = sum(1 for r in rows if (r[a]["vulnerable"] == bool(r["label"])) and (r[b]["vulnerable"] != bool(r["label"])))
    only_b = sum(1 for r in rows if (r[b]["vulnerable"] == bool(r["label"])) and (r[a]["vulnerable"] != bool(r["label"])))
    return {"only_" + a + "_correct": only_a, "only_" + b + "_correct": only_b,
            "p_value": round(mcnemar_exact(only_a, only_b), 6)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasets", required=True)
    ap.add_argument("--semgrep", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--modes", default="framework")
    ap.add_argument("--scan-cwd", default=".")
    a = ap.parse_args()
    modes = [m for m in a.modes.split(",") if m]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    units = all_units(a.datasets)
    by_file = load_semgrep(a.semgrep, a.scan_cwd)
    rows = []
    for i, u in enumerate(units, 1):
        f = unit_findings(u, by_file)
        r = {"id": u["id"], "dataset": u["dataset"], "label": u["label"], "cwe": u["cwe"],
             "n_files": len(u["files"]), "semgrep_findings": len(f),
             "semgrep": {"vulnerable": bool(f), "cwe": sorted({c for x in f for c in x["cwe"]})}}
        if "framework" in modes:
            r["framework"] = ask(u, f, True)
        if "llm_only" in modes:
            r["llm_only"] = ask(u, f, False)
        rows.append(r)
        print(f"[{i}/{len(units)}] {u['id']} label={u['label']} semgrep={len(f)}"
              + "".join(f" {m}={int(r[m]['vulnerable'])}" for m in modes), flush=True)

    dets = ["semgrep"] + modes
    res = {"mock": llm.MOCK, "model": llm.MODEL, "modes": modes, "per_dataset": {}, "overall": {}}
    for d in dets:
        per = {ds: score([r for r in rows if r["dataset"] == ds], d) for ds in DATASETS
               if any(r["dataset"] == ds for r in rows)}
        pooled = score(rows, d)
        macro = round(sum(p["DDR"] for p in per.values()) / len(per), 2)
        cwe_rows = [r for r in rows if r["cwe"]]
        res["per_dataset"][d] = per
        res["overall"][d] = {"pooled": pooled, "macro_DDR": macro,
                             "cwe_matched_DDR_webgoat_dvwa": score(cwe_rows, d, cwe_match=True)["DDR"]}
    res["mcnemar"] = {}
    for m in modes:
        res["mcnemar"][f"{m}_vs_semgrep"] = {
            "all_units": compare(rows, m, "semgrep"),
            "positives_only": compare([r for r in rows if r["label"] == 1], m, "semgrep"),
        }
    if "framework" in modes and "llm_only" in modes:
        res["mcnemar"]["framework_vs_llm_only"] = {"all_units": compare(rows, "framework", "llm_only")}
    res["unparsed_llm_responses"] = sum(1 for r in rows for m in modes if r[m].get("unparsed"))

    (out / "detection_units.json").write_text(json.dumps(rows, indent=1))
    (out / "detection_results.json").write_text(json.dumps(res, indent=1))
    md = to_markdown(res)
    (out / "detection_results.md").write_text(md)
    print(md)


def to_markdown(res):
    L = []
    if res["mock"]:
        L.append("> **MOCK RUN: LLM answers are placeholders. Do not use these numbers.**\n")
    L.append(f"### Detection results (model: {res['model']})\n")
    L.append("| Detector | Benchmark | Units | TP | FN | FP | TN | DDR % (95% CI) | Precision % | FPR % | F1 |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for d, per in res["per_dataset"].items():
        for ds, s in list(per.items()) + [("pooled", res["overall"][d]["pooled"])]:
            ci = s["DDR_95CI"]
            L.append(f"| {d} | {ds} | {s['units']} | {s['TP']} | {s['FN']} | {s['FP']} | {s['TN']} | "
                     f"{s['DDR']} ({ci[0]}-{ci[1]}) | {s['precision']} | {s['FPR']} | {s['F1']} |")
    L.append("\n| Detector | Macro DDR % | Pooled DDR % | CWE-matched DDR % (WebGoat+DVWA) |")
    L.append("|---|---|---|---|")
    for d, o in res["overall"].items():
        L.append(f"| {d} | {o['macro_DDR']} | {o['pooled']['DDR']} | {o['cwe_matched_DDR_webgoat_dvwa']} |")
    L.append("\n| Comparison | Units | Only first correct | Only second correct | Exact McNemar p |")
    L.append("|---|---|---|---|---|")
    for name, v in res["mcnemar"].items():
        for scope, c in v.items():
            vals = list(c.values())
            L.append(f"| {name} | {scope} | {vals[0]} | {vals[1]} | {vals[2]} |")
    L.append(f"\nUnparsed LLM responses: {res['unparsed_llm_responses']}")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
