"""Pytest wrapper that parametrises every rule's positive/negative cases.

Run locally with:  pytest -v
This produces one test per sample event, so failures pinpoint the exact case.
"""
import os
import sys
import glob
import json
import yaml
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "runner"))
from sigma_test import rule_matches, find_tests  # noqa: E402

RULES_DIR = "rules"
TESTS_DIR = "tests"


def _load(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def _collect():
    cases = []
    for rf in sorted(glob.glob(os.path.join(RULES_DIR, "**", "*.yml"), recursive=True)):
        with open(rf) as f:
            rule = yaml.safe_load(f)
        title = rule.get("title", rf)
        tdir = find_tests(rf, TESTS_DIR)
        assert tdir, f"Rule has no test data: {title}"
        for i, ev in enumerate(_load(os.path.join(tdir, "positive.jsonl"))):
            cases.append(pytest.param(rule, ev, True, id=f"{title}::positive#{i+1}"))
        for i, ev in enumerate(_load(os.path.join(tdir, "negative.jsonl"))):
            cases.append(pytest.param(rule, ev, False, id=f"{title}::negative#{i+1}"))
    return cases


@pytest.mark.parametrize("rule,event,should_match", _collect())
def test_detection(rule, event, should_match):
    result = rule_matches(rule, event)
    if should_match:
        assert result, "rule failed to match a known-malicious event (detection gap)"
    else:
        assert not result, "rule matched a benign event (false positive)"
