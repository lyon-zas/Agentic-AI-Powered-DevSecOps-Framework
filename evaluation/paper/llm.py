"""
Minimal Gemini client for the paper evaluation.

Calls the Gemini REST API directly (temperature 0, JSON output) so the
evaluation does not depend on the ADK runtime. Responses are cached on disk
by a hash of (model, prompt), so a rerun after a rate-limit failure resumes
instead of starting over.

Set LLM_MOCK=1 to run without an API key. Mock answers are placeholders for
testing the pipeline only and every output file produced in that mode is
marked "mock": true.
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

import requests

MODEL = os.getenv("EVAL_MODEL", "gemini-2.0-flash")
MOCK = os.getenv("LLM_MOCK") == "1"
CACHE = Path(os.getenv("LLM_CACHE_DIR", "evaluation/paper/.llm_cache"))
RPM = float(os.getenv("LLM_RPM", "10"))
_last = [0.0]


def _key(prompt):
    return hashlib.sha256(f"{MODEL}\n{prompt}".encode()).hexdigest()


def generate_json(prompt, mock=None, max_retries=6):
    """Return (parsed_json, seconds_spent_in_api, cached)."""
    if MOCK:
        return (mock() if callable(mock) else mock or {}), 0.0, False
    CACHE.mkdir(parents=True, exist_ok=True)
    f = CACHE / (_key(prompt) + ".json")
    if f.exists():
        d = json.loads(f.read_text())
        return d["response"], d["seconds"], True

    api_key = os.environ["GOOGLE_API_KEY"]
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
    }
    for attempt in range(max_retries):
        wait = 60.0 / RPM - (time.time() - _last[0])
        if wait > 0:
            time.sleep(wait)
        _last[0] = time.time()
        t0 = time.perf_counter()
        r = requests.post(url, params={"key": api_key}, json=body, timeout=180)
        dt = time.perf_counter() - t0
        if r.status_code in (429, 500, 502, 503, 504):
            time.sleep(min(120, 5 * 2 ** attempt))
            continue
        if not r.ok:
            raise RuntimeError(f"Gemini API {r.status_code} for model '{MODEL}': {r.text[:300]}")
        try:
            text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
            out = _parse(text)
        except (KeyError, IndexError, ValueError):
            out = {"_unparsed": r.text[:2000]}
        f.write_text(json.dumps({"model": MODEL, "seconds": dt, "response": out}))
        return out, dt, False
    raise RuntimeError(f"Gemini request failed after {max_retries} attempts: {r.status_code} {r.text[:300]}")


def _parse(text):
    try:
        return json.loads(text)
    except ValueError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        return json.loads(m.group(0))
