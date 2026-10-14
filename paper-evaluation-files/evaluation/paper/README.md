# Paper evaluation (AJERD revision)

Reproduces the detection, significance and remediation figures reported in the paper.

- `ground_truth.py`: labelled units. DVWA = module x security level (low/medium/high vulnerable, impossible secure); Juice Shop = coding-challenge snippets (`*_correct` secure, other variants vulnerable); WebGoat = vulnerability lessons (all vulnerable). 228 units: 174 vulnerable, 54 secure.
- `run_detection.py`: Semgrep alone vs the framework's SAST agent (Gemini given code + Semgrep findings), optional LLM-only ablation. DDR with Wilson 95% CI, precision, FPR, F1, macro and pooled DDR, exact McNemar test.
- `run_remediation_timing.py`: for each vulnerable Juice Shop snippet, times analysis, LLM fix, README generation and PR (dry run); reports MTTR and BLEU against the `*_correct` fix, plus a no-change BLEU baseline.
- `llm.py`: Gemini REST client, temperature 0, JSON output, on-disk cache. `LLM_MOCK=1` runs without a key (placeholder answers, marked as mock).

Run it from GitHub: Actions > "Paper Evaluation (AJERD revision)" > Run workflow. Needs the `GOOGLE_API_KEY` repository secret. Results appear on the run's summary page and in the `paper-evaluation-results` artifact.
