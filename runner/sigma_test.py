#!/usr/bin/env python3
"""
sigma_test.py - Self-contained detection-rule test runner.

Evaluates Sigma rule logic against positive (must-match) and negative
(must-not-match) sample log events, and fails if any rule does not behave
as its tests expect. Designed to run in CI on every commit with no external
services and minimal dependencies (PyYAML only).

This implements the subset of Sigma detection semantics used by web/SIEM
log rules: field matchers with modifiers (contains, startswith, endswith,
re, all), value lists (OR), multi-field selections (AND), and conditions
built from selection identifiers with and/or/not and "N of selection*".

For full Sigma coverage in production, this evaluator can be swapped for
pySigma-based evaluation; the test-data format and CI gate stay identical.
"""
import json
import re
import sys
import glob
import os
import argparse

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")


# ---- field-level matching -------------------------------------------------

def _as_list(v):
    return v if isinstance(v, list) else [v]


def match_field(event_value, modifiers, expected):
    """Return True if a single event field value satisfies one expected value."""
    if event_value is None:
        return False
    ev = str(event_value)
    exp = str(expected)

    if "re" in modifiers:
        return re.search(exp, ev) is not None
    if "contains" in modifiers:
        return exp in ev
    if "startswith" in modifiers:
        return ev.startswith(exp)
    if "endswith" in modifiers:
        return ev.endswith(exp)
    # default: Sigma plain match supports '*' wildcards, case-insensitive
    if "*" in exp:
        pattern = "^" + re.escape(exp).replace(r"\*", ".*") + "$"
        return re.match(pattern, ev, re.IGNORECASE) is not None
    return ev.lower() == exp.lower()


def match_selection(event, selection):
    """A selection is a dict of {field|modifiers: value(s)}. All keys must match (AND).

    For a single key, a list of values means OR, unless the 'all' modifier is set.
    """
    if isinstance(selection, list):
        # list of maps / keywords -> OR
        return any(match_selection(event, s) for s in selection)
    if not isinstance(selection, dict):
        # bare keyword: match against all event values
        return any(str(selection).lower() in str(v).lower() for v in event.values())

    for key, expected in selection.items():
        parts = key.split("|")
        field = parts[0]
        modifiers = parts[1:]
        values = _as_list(expected)
        event_value = event.get(field)

        if "all" in modifiers:
            ok = all(match_field(event_value, modifiers, v) for v in values)
        else:
            ok = any(match_field(event_value, modifiers, v) for v in values)
        if not ok:
            return False
    return True


# ---- condition evaluation -------------------------------------------------

def evaluate_condition(condition, selections, event):
    """Evaluate a Sigma condition string against the selections for one event."""
    results = {name: match_selection(event, sel) for name, sel in selections.items()}

    # Handle "N of selection*" / "all of them" style aggregates by expansion.
    def expand(token_match):
        quant, pattern = token_match.group(1), token_match.group(2)
        if pattern in ("them", "*"):
            names = list(results.keys())
        else:
            regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
            names = [n for n in results if re.match(regex, n)]
        joined = " , ".join(names) if names else "False"
        if quant == "all":
            return "( " + " and ".join(names) + " )" if names else "False"
        else:  # "1 of" / "N of" -> treat as OR (at least one)
            return "( " + " or ".join(names) + " )" if names else "False"

    expr = condition
    expr = re.sub(r"\b(all|1|\d+)\s+of\s+([A-Za-z0-9_*]+|them)", expand, expr)

    # Replace selection names with their boolean values
    for name in sorted(results, key=len, reverse=True):
        expr = re.sub(rf"\b{name}\b", "True" if results[name] else "False", expr)

    expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace(" not ", " not ")
    # Only booleans/operators/parens remain -> safe to evaluate
    if not re.fullmatch(r"[\sTrueFalsenotandor()]*", expr):
        raise ValueError(f"Unsafe/unsupported condition expression: {expr}")
    return bool(eval(expr))  # noqa: S307 - sanitised to booleans only


def rule_matches(rule, event):
    detection = rule["detection"]
    condition = detection["condition"]
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if isinstance(condition, list):
        condition = " or ".join(f"({c})" for c in condition)
    return evaluate_condition(condition, selections, event)


# ---- test harness ---------------------------------------------------------

def load_events(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def find_tests(rule_path, tests_root):
    base = os.path.splitext(os.path.basename(rule_path))[0]
    matches = glob.glob(os.path.join(tests_root, "**", base), recursive=True)
    return matches[0] if matches else None


def run(rules_dir, tests_dir):
    rule_files = glob.glob(os.path.join(rules_dir, "**", "*.yml"), recursive=True)
    total, passed, failures = 0, 0, []

    for rf in sorted(rule_files):
        with open(rf) as f:
            rule = yaml.safe_load(f)
        tdir = find_tests(rf, tests_dir)
        title = rule.get("title", os.path.basename(rf))
        if not tdir:
            failures.append(f"[NO TESTS]   {title}  ({rf})")
            continue

        pos = load_events(os.path.join(tdir, "positive.jsonl"))
        neg = load_events(os.path.join(tdir, "negative.jsonl"))

        rule_ok = True
        for i, ev in enumerate(pos):
            total += 1
            if rule_matches(rule, ev):
                passed += 1
            else:
                rule_ok = False
                failures.append(f"[MISS]       {title}: positive case #{i+1} did NOT match")
        for i, ev in enumerate(neg):
            total += 1
            if not rule_matches(rule, ev):
                passed += 1
            else:
                rule_ok = False
                failures.append(f"[FALSE POS]  {title}: negative case #{i+1} matched")

        status = "PASS" if rule_ok else "FAIL"
        print(f"  [{status}] {title}  ({len(pos)} positive, {len(neg)} negative)")

    print(f"\n{passed}/{total} test cases passed across {len(rule_files)} rule(s).")
    if failures:
        print("\nFailures:")
        for fmsg in failures:
            print("  " + fmsg)
        return 1
    print("All detection tests passed.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Run detection-rule logic tests.")
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--tests", default="tests")
    sys.exit(run(ap.parse_args().rules, ap.parse_args().tests))
