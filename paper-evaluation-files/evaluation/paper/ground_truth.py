"""
Ground truth for the paper evaluation.

Each benchmark is split into labelled *units* (a file or a small group of files)
so detection can be scored against a documented reference instead of a
hand-entered total:

- DVWA: every module under vulnerabilities/*/source is shipped at four security
  levels. low/medium/high are exploitable by design (positives); impossible is the
  secure reference implementation (negative). Unit = (module, level).
- OWASP Juice Shop: data/static/codefixes holds the "coding challenge" snippets.
  For each challenge, the *_correct variant is the secure fix (negative); every
  other variant is a rejected fix that leaves the vulnerability in place
  (positive). Unit = one snippet file.
- WebGoat: every vulnerability lesson under lessons/<name> is deliberately
  vulnerable (positive). WebGoat ships no secure counterparts, so it contributes
  to detection rate only, not to precision. Unit = lesson.
"""
import re
from pathlib import Path

DVWA_CWE = {
    "api": ["CWE-284"], "authbypass": ["CWE-285"], "bac": ["CWE-639"],
    "brute": ["CWE-307"], "captcha": ["CWE-804"], "cryptography": ["CWE-327"],
    "csp": ["CWE-693"], "csrf": ["CWE-352"], "exec": ["CWE-78"], "fi": ["CWE-98"],
    "javascript": ["CWE-602"], "open_redirect": ["CWE-601"], "sqli": ["CWE-89"],
    "sqli_blind": ["CWE-89"], "upload": ["CWE-434"], "weak_id": ["CWE-330"],
    "xss_d": ["CWE-79"], "xss_r": ["CWE-79"], "xss_s": ["CWE-79"],
}
DVWA_LEVELS = {"low": 1, "medium": 1, "high": 1, "impossible": 0}

WEBGOAT_CWE = {
    "authbypass": ["CWE-287"], "bypassrestrictions": ["CWE-602"], "challenges": ["CWE-287"],
    "clientsidefiltering": ["CWE-602"], "commandinjection": ["CWE-78"],
    "cryptography": ["CWE-327"], "csrf": ["CWE-352"], "deserialization": ["CWE-502"],
    "hijacksession": ["CWE-384"], "htmltampering": ["CWE-472"],
    "httpparameterpollution": ["CWE-235"], "idor": ["CWE-639"], "insecurelogin": ["CWE-319"],
    "jwt": ["CWE-347"], "logging": ["CWE-532"], "missingac": ["CWE-285"],
    "openredirect": ["CWE-601"], "passwordreset": ["CWE-640"], "passwordstorage": ["CWE-916"],
    "pathtraversal": ["CWE-22"], "securitymisconfiguration": ["CWE-16"],
    "spoofcookie": ["CWE-565"], "sqlinjection": ["CWE-89"], "ssrf": ["CWE-918"],
    "vulnerablecomponents": ["CWE-1104"], "xss": ["CWE-79"], "xxe": ["CWE-611"],
}
# Introductory lessons with no deliberate vulnerability are left out:
# chromedevtools, cia, httpbasics, httpproxies, lessontemplate, securepasswords,
# webauthn, webgoatintroduction, webwolfintroduction.

CODE_EXT = (".php", ".js", ".ts", ".java", ".sol", ".yml", ".yaml", ".tf", ".html")


def dvwa_units(root):
    units = []
    for module, cwe in DVWA_CWE.items():
        src = Path(root) / "vulnerabilities" / module / "source"
        if not src.is_dir():
            continue
        for level, label in DVWA_LEVELS.items():
            pat = re.compile(rf"(?:\w+_)?{level}(?:_unobfuscated)?\.(php|js)")
            files = sorted(str(p) for p in src.iterdir() if pat.fullmatch(p.name))
            if files:
                units.append({"dataset": "dvwa", "id": f"dvwa:{module}:{level}", "files": files,
                              "label": label, "cwe": cwe})
    return units


def juice_shop_units(root):
    import yaml
    root = Path(root)
    cats = {}
    chal = root / "data" / "static" / "challenges.yml"
    if chal.exists():
        for c in yaml.safe_load(chal.read_text()) or []:
            cats[c.get("key")] = c.get("category", "")
    units = []
    for p in sorted((root / "data" / "static" / "codefixes").iterdir()):
        if p.name.endswith(".info.yml") or not p.name.endswith(CODE_EXT):
            continue
        key = p.name.split("_")[0]
        units.append({"dataset": "juice-shop", "id": f"juice-shop:{p.stem}", "files": [str(p)],
                      "label": 0 if "_correct" in p.name else 1,
                      "challenge": key, "category": cats.get(key, ""), "cwe": []})
    return units


def webgoat_units(root):
    root = Path(root)
    java = root / "src" / "main" / "java" / "org" / "owasp" / "webgoat" / "lessons"
    res = root / "src" / "main" / "resources" / "lessons"
    units = []
    for lesson, cwe in WEBGOAT_CWE.items():
        files = []
        for base in (java / lesson, res / lesson / "js"):
            if base.is_dir():
                files += sorted(str(p) for p in base.rglob("*") if p.is_file() and p.name.endswith(CODE_EXT))
        if files:
            units.append({"dataset": "webgoat", "id": f"webgoat:{lesson}", "files": files,
                          "label": 1, "cwe": cwe})
    return units


def all_units(datasets_dir):
    d = Path(datasets_dir)
    units = []
    if (d / "dvwa").is_dir():
        units += dvwa_units(d / "dvwa")
    if (d / "juice-shop").is_dir():
        units += juice_shop_units(d / "juice-shop")
    if (d / "webgoat").is_dir():
        units += webgoat_units(d / "webgoat")
    return units


if __name__ == "__main__":
    import sys, collections
    us = all_units(sys.argv[1] if len(sys.argv) > 1 else "evaluation/datasets")
    c = collections.Counter((u["dataset"], u["label"]) for u in us)
    for k in sorted(c):
        print(k, c[k])
