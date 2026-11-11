# Architecture

```
app.py                 Streamlit UI (7 pages), reads/writes through database/ and engine/
config/settings.py     Paths, env, canaries, default system prompt, scoring weights
attacks/library.py     39 AttackCase definitions (9 attack categories + benign controls)
mock_target/target.py  Deterministic mock LLM: vulnerable | basic | hardened
engine/clients.py      MockClient and OpenAICompatibleClient (authorization gate)
engine/runner.py       Runs cases, evaluates, scores, persists
engine/scoring.py      Metrics and overall score
engine/documents.py    TXT/PDF/DOCX extraction, upload-to-case conversion
engine/samples.py      Generates sample adversarial documents
detectors/             canary, refusal, leakage, injection scanner, evaluate (verdict logic)
database/db.py         SQLite (assessments, results)
reports/exporters.py   JSON, CSV (formula-safe), PDF (reportlab)
scripts/               run_headless.py, publish_to_github.sh
tests/                 pytest suite
```

Data flow: `AttackCase -> client.send() -> response -> detectors.evaluate() -> result dict -> database + compute_score()`.

## Safety design

- The mock target is the default. `OpenAICompatibleClient` cannot be constructed without `authorized=True` and a typed hostname matching the base URL.
- Remote targets must use https. Cloud metadata hosts are blocked. Requests are paced with `PIAL_REQUEST_DELAY`.
- API keys come from the environment or the form, live only in memory, and are excluded from `describe()`, the database and reports.
- Target output is untrusted: the UI renders it as plain text, CSV export neutralises formula prefixes, and the PDF escapes markup.
- Payloads use harmless markers and synthetic canaries only.

## Mock target heuristics

The mock is not a model. `basic` blocks literal phrases (ignore, system prompt, DAN) but misses base64, spaced letters, split payloads, fake system turns, claimed authority, multi-step requests and document injection. `hardened` refuses any signal and flags poisoned documents. This gives reproducible results for demos and regression tests.
