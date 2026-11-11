# Prompt Injection Attack Lab (PIAL)

A local platform for testing LLM-powered applications against prompt injection, jailbreaks, system prompt extraction and indirect (document) injection. It runs fully offline against a built-in mock target, so no paid API is needed.

**Educational and professional security research only.** Attacks go to the mock target by default. External endpoints require explicit authorization.

## What it does

| Area | Details |
|---|---|
| Attack library | 36 attack probes in 9 categories plus 3 benign controls: instruction override, role manipulation, context manipulation, priority conflicts, malicious injection, jailbreaks, system prompt extraction, indirect injection, guardrail evaluation |
| Verdicts | `confirmed`, `suspected`, `inconclusive`, `resisted`, each with evidence and confidence |
| Detectors | Canary exposure (exact, spaced, reversed, base64), refusal, prompt-overlap leakage, input injection scanner |
| Documents | Upload TXT, PDF or DOCX and test whether the target obeys instructions inside them |
| Scoring | Attack success rate, refusal rate, canary exposure, instruction-following vulnerability rate, false-refusal rate, 0 to 100 score with grade |
| Dashboard | Overview, New assessment, Attack library, Test history, Vulnerability analytics, Security reports, Settings |
| Reports | JSON, CSV (formula-injection safe) and PDF with date, target config, findings, severity, evidence, recommendations |

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/JamestheBuildrCodes/prompt-injection-attack-lab.git
cd prompt-injection-attack-lab
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Open the URL Streamlit prints, then click **Run demo assessment** on Overview.

No API key and no `.env` file are required. Copy `.env.example` to `.env` only to pre-fill external endpoint defaults.

## Mock target

Three deterministic defence levels let you see every verdict type:

- `vulnerable`: obeys injections and leaks its prompt (should score near 0)
- `basic`: keyword filter that blocks blatant phrases but misses obfuscation, personas, fake system turns and document injection
- `hardened`: refuses injections and flags poisoned documents (should score near 100)

## Testing an external endpoint (authorized use only)

1. New assessment, choose **External OpenAI-compatible endpoint**.
2. Enter base URL (https, or http on localhost), model and API key (or set `PIAL_API_KEY`).
3. Tick the authorization box and type the exact hostname to confirm.

The key stays in memory. It is never written to the database, reports or logs. Replace the default system prompt with your own, but keep the synthetic canaries so leaks can be detected. Never put real secrets in the prompt you test.

## Command line

```bash
python scripts/run_headless.py --defense basic --export exports/
```

## Tests

```bash
pytest
```

Covers attack execution, scoring, injection detection, canary detection, verdict logic, database operations, document handling, report generation and the authorization gate. All tests run offline.

## Screenshots

See [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md) for how to capture them into `assets/screenshots/`.

## Documentation

- [Architecture and safety design](docs/ARCHITECTURE.md)
- [Scoring and verdicts](docs/SCORING.md)
- [Attack library](docs/ATTACK_LIBRARY.md)

## Responsible use

Only test systems you own or have written permission to test. Probes use harmless markers and synthetic canaries, but they still generate traffic. Findings are heuristic and should be reviewed by a person before you act on them.

## License

MIT
