# Detection Testing in CI (Test-Driven Detection)

Detection-as-Code lets you version, review, and deploy detection rules like
software. But deploying a rule is not the same as knowing it *works*. A rule
can silently fail to match a real attack, or quietly flood analysts with false
positives. This project adds the missing piece: **automated testing of
detection rules in CI**, so a rule cannot ship unless it provably matches
known-malicious activity and ignores known-benign activity.

## How it works

Every rule is paired with test data:

```
rules/web/webshell_command_injection.yml          # the Sigma rule
tests/web/webshell_command_injection/
    positive.jsonl   # events that MUST match   (true positives)
    negative.jsonl   # events that must NOT match (true negatives)
```

On every commit, the CI pipeline evaluates each rule against its samples and
**fails the build** if the rule misses a positive (a detection gap) or matches
a negative (a false positive). Only rules that pass can merge and deploy
through the Detection-as-Code pipeline.

The sample data here is drawn from a **real incident**: a Next.js
React2Shell (CVE-2025-55182) compromise that led to a coin miner. The
malicious requests become positive tests; the benign traffic that was
analysed and ruled out (legitimate Next.js `_rsc` navigation, harmless
scanner 404s) becomes negative tests.

## Run it

```bash
pip install -r requirements.txt

# Summary runner (primary CI gate, exits non-zero on failure)
python runner/sigma_test.py --rules rules --tests tests

# Per-case view
pytest -v
```

## Why a self-contained evaluator

The runner implements the subset of Sigma detection semantics used by web and
SIEM log rules (field modifiers, value lists, multi-field selections, and
conditions). This keeps CI fast and dependency-free. For full Sigma coverage,
the evaluation layer can be replaced with pySigma-based matching; the test-data
format and the CI gate stay identical.

## Layout

```
rules/        Sigma detection rules
tests/        positive/negative sample events per rule
runner/       sigma_test.py - the logic evaluator + summary runner
test_detections.py   pytest wrapper (one test per sample)
.github/workflows/detection-tests.yml   CI gate
```
