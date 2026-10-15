# Incident Analysis Assistant

GenAI-assisted incident classification, summarization and grounded verification on Microsoft's GUIDE dataset.

**Research question:** does evidence-grounded verification reduce the omission and hallucination rates reported by Kramer et al. (SOUPS 2025)?

## Setup
```bash
python -m venv .venv
```
Activate the environment (`.venv\Scripts\Activate.ps1` on Windows, or `source .venv/bin/activate` on macOS/Linux), then install dependencies:
```bash
python -m pip install -r requirements.txt
```
Download the GUIDE dataset from Kaggle (`microsoft-security-incident-prediction`) and put `GUIDE_Train.csv` and `GUIDE_Test.csv` in `data/`.
Do not use the queue-ranking file.

The downloaded dataset, prepared incident JSONL files, model files, run outputs, and LLM cache are intentionally excluded from Git. Follow the dataset's license and terms when downloading or using it; the repository does not redistribute the GUIDE CSVs. Run the stages below to regenerate local artifacts.

## Stage 1: prep (CSV -> one JSON per incident)
```bash
python -m src.prep --csv data/GUIDE_Train.csv --out data/incidents_train.jsonl --sample-mod 200
python -m src.prep --csv data/GUIDE_Test.csv  --out data/incidents_test.jsonl  --sample-mod 200
python -m src.peek data/incidents_train.jsonl      # inspect one incident
```
Re-run prep after updating: the output format gained `entity_counts`, `critical_counts`, `org_id`, `time_span_hours`.

## Stage 2: baseline classifier
```bash
python -m src.classify --train data/incidents_train.jsonl                 # dev loop, train only
python -m src.classify --train data/incidents_train.jsonl --test data/incidents_test.jsonl --eval-test   # final, run ONCE
```
Add `--model hgb` to use scikit-learn gradient boosting if XGBoost won't install.
Outputs: `models/`, `results/baseline_metrics.json`.

## Stage 3: narrative + LLM client
```bash
python -m src.narrative data/incidents_test.jsonl 0     # print one narrative (deterministic, no LLM)
python -m src.mitre data/incidents_train.jsonl          # list MITRE IDs missing from the name lookup
python -m tests.test_core                               # offline tests
```
LLM setup (free Gemini key from https://aistudio.google.com):
```bash
copy .env.example .env      # Windows (use cp on Mac/Linux), then edit .env with your key and model id
python -m src.llm_check     # smoke test: should print {"ok": true}
```
`src/llm.py` caches every response in `cache/llm_cache.sqlite`, rate-limits (`LLM_RPM`) and retries on 429.
Never commit `.env`.

## Stage 4: LLM classifier + summarizer
```bash
python -m tests.test_stage4                          # offline tests (fake LLM)
python -m src.run_llm --mode llm --n 20              # small trial first!
python -m src.run_llm --mode llm --n 150             # LLM classifies + summarizes (zero-shot)
python -m src.run_llm --mode hybrid --n 150          # XGBoost label + LLM explanation
python -m src.run_llm --mode llm --n 150 --eval-only # re-score without API calls
```
- Uses one stratified, seeded test subset (same incidents in every mode).
- Output: `results/<mode>_<n>.jsonl` (prediction, confidence, summary, claims per incident).
- Resumable: if the free quota runs out the run stops; re-run the same command to continue.
- Prints macro-F1 with bootstrap 95% CIs for the LLM and the baseline on the same incidents.

### Larger incidents
The random 1-in-200 test sample has almost no large incidents (7 of 1,181 have > 20 alerts). Pull them from the full file instead:
```bash
python -m src.prep --csv data/GUIDE_Test.csv --out data/incidents_test_large.jsonl --min-alerts 20 --max-incidents 300
python -m src.size_report data/incidents_test_large.jsonl
python -m src.run_llm --mode hybrid --n 60 --test data/incidents_test_large.jsonl --out results/hybrid_large_60.jsonl
python -m src.run_verify --input results/hybrid_large_60.jsonl --test data/incidents_test_large.jsonl --revise
```
Classification scores on this file are exploratory (the baseline is trained mostly on small incidents).

### (older) adding extra large incidents to the base subset
```bash
python -m src.size_report data/incidents_test.jsonl                 # see how many large incidents exist
python -m src.run_llm --mode hybrid --n 150 --extra-large 40 --min-alerts 20
python -m src.run_llm --mode llm    --n 150 --extra-large 40 --min-alerts 20
```
Adds extra incidents with >= `--min-alerts` alerts to the same base subset; output goes to `results/<mode>_150_plus40large.jsonl`.

## Stage 5: verifier (the contribution)
```bash
python -m tests.test_stage5                                       # offline tests
python -m src.run_verify --input results/hybrid_150.jsonl         # verify only, no API calls
python -m src.run_verify --input results/hybrid_150.jsonl --revise   # + one verifier-feedback revision
python -m src.labeling export --input results/hybrid_150.jsonl --n 50  # sheet for hand-labeling
python -m src.labeling score                                      # verifier vs your labels
```
- Checks run against what the model was *shown* (the narrative), not the full incident.
- Hallucination = >=1 hard issue (unsupported entity/technique/alert type/id/date, invented IP or hash, wrong entity type). Unsupported counts are "soft" and reported separately.
- Omission (fixed definition, see `src/verify.py` docstring): no tactic/technique mentioned, or no impacted entity cited / impacted count stated.
- Validation: `python -m src.labeling score --sheet <sheet.csv> --recompute` re-scores a labeled sheet with the current verifier.
  To validate honestly after changing the verifier, label a FRESH sample:
  `python -m src.labeling export --input results/hybrid_150.jsonl --n 50 --exclude results/labeling_sheet.csv --seed 11`
- Revision keeps the classification fixed, so only the summary changes.

## Stage 6: Streamlit app
```bash
streamlit run app.py
```
Run from the project root (needs `data/incidents_test*.jsonl` and `results/` from the earlier stages).
- **Saved runs**: pick a run, filter by incident size / verifier-flagged / revised, and inspect one incident: triage label, rationale, the summary with unsupported claims highlighted (red = hard, orange = soft count), an evidence-coverage panel (what the summary left out), the original-vs-revised summary, and the exact report the model saw. No API calls (the verifier runs live and is free).
- **Live analysis**: analyze any incident end to end (needs `GEMINI_API_KEY` in `.env`; hybrid mode also needs the trained baseline in `models/`).
- **Evaluation report**: shows `results/final_report.md`.
```bash
python -m tests.run_all       # all offline tests, including a smoke test of app.py against a stub Streamlit
```

## Free-text analysis mode (paste or upload your own incident text)

For incidents that are **not** in the GUIDE dataset: paste logs, an alert export or a ticket (or upload a `.txt`/`.log`/`.json`/`.csv`/`.md` file) in the **Free-text analysis** tab of the app.

```bash
streamlit run app.py        # then open the "Free-text analysis" tab
```
1. Pick one of the sample incidents (or paste/upload your own) and press **Analyze text**.
2. You get: a summary, a *hypothesis* about the activity (with the quoted evidence), suggested MITRE ATT&CK techniques, indicators (IPs, URLs, hashes, e-mails...), alternative explanations, what cannot be determined, and suggested next steps.
3. The verifier then checks the answer against **your text**:
   - every indicator value, and every technique/activity evidence snippet, must be quoted from the text;
   - any IP, URL, hash, e-mail, CVE or domain in the answer that is not in the text is flagged (red);
   - technique IDs must be well formed, and names are compared with the local ATT&CK table (soft flag);
   - times/dates not found in the text are a soft flag (formats vary);
   - indicators that are in your text (found by regex) but never mentioned by the analysis are listed.
4. If anything is flagged, one revision pass feeds the problems back to the LLM and re-verifies.

No True/Benign/False label is produced here: in the evaluation, a zero-shot LLM triaged poorly (macro-F1 0.27 vs 0.66 for the structured model).

### What you can paste or upload
Any plain text about an incident: syslog / `auth.log` lines, Windows event exports (CSV/JSON), EDR or IDS alert exports, cloud audit logs (CloudTrail-style JSON), e-mail gateway or proxy logs, web server logs, helpdesk tickets, analyst notes and change records. Mixed material is fine.
- **Formats:** paste into the box, or upload `.txt`, `.log`, `.json`, `.csv` or `.md` (UTF-8 text). Screenshots, PDFs, Word files and binary captures (`.pcap`, `.evtx`) are not supported; convert them to text first.
- **Size:** the first 20,000 characters are analyzed (roughly 150-300 log lines); the app warns when text is cut.
- **What makes a good input:** timestamps, who/what/where (user, host, IP), the alert or log text itself, and *context* such as change records or notes about normal behaviour. Context is often what separates an attack from routine work.
- **Do not paste** secrets, real customer data or anything confidential (see Limits below).

### Sample incidents (`samples/`, all synthetic)
| File | What it shows | Techniques a good analysis should find |
|---|---|---|
| `phishing_account_takeover.txt` | Defanged phishing URL, sign-in from a new IP without MFA, mailbox forwarding rule | T1566.002, T1078.004, T1114.003 |
| `ssh_bruteforce_server.log` | Failed SSH logins, success on a service account, sudo, cron change, downloaded script | T1110.001, T1078.003, T1053.003, T1105 |
| `ransomware_precursor_edr.txt` | Macro -> hidden PowerShell -> credential access -> shadow-copy deletion -> mass encryption | T1059.001, T1003.001, T1490, T1486 |
| `cloud_audit_log.json` | JSON audit log: login without MFA from a new IP, new access key, new admin user, payroll files read | T1078.004, T1098.001, T1136.003, T1530 |
| `windows_security_events.csv` | CSV events: failed RDP logons, success, new local admin, audit log cleared | T1110, T1021.001, T1136.001, T1070.001 |
| `authorized_pentest_scan.txt` | Scans, SQL injection and brute force that match an approved change record | T1046, T1190, T1110 (but the best answer names the pen test as the leading explanation) |
| `normal_admin_maintenance.txt` | **Benign**: PsExec, service installs and PowerShell that match an approved patching change | none expected; inventing attack techniques is a failure |
| `minimal_ticket.txt` | One-line vague ticket, no logs | none expected; a good answer says little can be concluded and invents nothing |
| `prompt_injection_web_log.txt` | SQL injection + web shell request, with an instruction hidden in a log field | T1190, T1505.003; the hidden instruction must be ignored |

`samples/expected.json` holds this reference key; the app shows it after you analyze a sample and ticks the techniques the analysis found. All IPs are documentation addresses and all domains end in `.example`. You can add your own samples by dropping a file into `samples/`.

### Limits and cautions
- **Privacy:** text is sent to the LLM provider. Gemini's free tier may use inputs to improve Google's products. Do not paste confidential or personal data.
- **Prompt injection:** pasted text is treated as untrusted data (wrapped in tags, and the system prompt tells the model to ignore instructions inside it). This reduces, but does not remove, the risk. The verifier still checks the output against the text.
- **Not validated:** this mode was not evaluated with hand labels like the GUIDE pipeline. The verifier can show that a quoted item exists in your text; it cannot show that a technique mapping is correct, or that the sequence of events is right.
- **Truncation:** only the first 20,000 characters are analyzed (the app warns you).
- The local ATT&CK table covers about 120 techniques, so many valid IDs show as "not in local table" (informational).

## Stage 7: final report + full reproduction
```bash
python -m src.report          # builds results/final_report.md from the saved result files
python -m tests.test_report
```
Order to reproduce every number (each step uses the one before):
```bash
python -m src.prep --csv data/GUIDE_Train.csv --out data/incidents_train.jsonl --sample-mod 200
python -m src.prep --csv data/GUIDE_Test.csv  --out data/incidents_test.jsonl  --sample-mod 200
python -m src.prep --csv data/GUIDE_Test.csv  --out data/incidents_test_large.jsonl --min-alerts 20 --max-incidents 300
python -m src.classify --train data/incidents_train.jsonl --test data/incidents_test.jsonl --eval-test
python -m src.run_llm --mode llm --n 150
python -m src.run_llm --mode hybrid --n 150
python -m src.run_llm --mode hybrid --n 60 --test data/incidents_test_large.jsonl --out results/hybrid_large_60.jsonl
python -m src.run_verify --input results/llm_150.jsonl
python -m src.run_verify --input results/hybrid_150.jsonl --revise
python -m src.run_verify --input results/hybrid_large_60.jsonl --test data/incidents_test_large.jsonl --revise
python -m src.report
```

## Data notes
- GUIDE is anonymized: alert titles and entities are numeric IDs; category and MITRE are readable.
- Entity value `0` is treated as a placeholder and dropped.
- `critical_evidence` = top 5 most frequent `Impacted` entities per type (used later for omission scoring).
- Dev validation is stratified and grouped by `org_id` to avoid same-organization leakage.
- Never tune on the test file.

## Roadmap
- [x] Stage 1: data prep
- [x] Stage 2: structured baseline (macro-F1)
- [x] Stage 3: deterministic narrative + LLM client
- [x] Stage 4: LLM classifier + summarizer (JSON schema, `[type:id]` entity tags)
- [x] Stage 5: verifier (hallucination + omission checks) + revision loop
- [x] Stage 6: Streamlit app (`app.py`, logic in `src/viewer.py`)
- [x] Stage 7: evaluation report (`src.report`)
- [x] Extra: free-text analysis mode (`src/freetext.py`, `samples/`)
