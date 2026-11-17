#!/usr/bin/env python3
"""Baseline quality gate for BLNCS.

Some production checks (flake8 full run, mypy, bandit) carry a large amount
of pre-existing findings.  Requiring "zero findings" for them keeps the
Production CI permanently red, and a gate that is always red is ignored --
it has negative value.  This script replaces the all-or-nothing requirement
with a *baseline freeze* (ratchet):

* The current per-category finding counts are recorded in
  ``ci/quality-baseline.json``.
* A gate passes when every category count is at or below its baseline.
* A gate fails when any category grows, or a category that is not in the
  baseline appears.  New findings therefore still turn CI red.
* When counts drop, the gate passes and prints a notice asking to ratchet
  the baseline down (``--update``), so the debt can only shrink over time.

The checks themselves are unchanged: the same tools run with the same
arguments as the previous hard gates (see ``docs/QUALITY_GATES.md``).

Usage:
    python scripts/quality_gate.py [flake8|mypy|bandit ...]
    python scripts/quality_gate.py all --update   # regenerate the baseline
    python scripts/quality_gate.py codeql --alerts alerts.json

The ``codeql`` gate is the one exception to "run the tool locally":
CodeQL findings live on GitHub's side, so the workflow fetches the open
alerts for main from the code-scanning API and hands the payload to this
script (``--alerts``).  Aggregation and comparison happen here, against
the same baseline file.  ``codeql`` is not part of ``all`` (a local run
has no payload to count) and its baseline cannot be regenerated with
``--update``; see docs/QUALITY_GATES.md.

Exit codes: 0 = pass, 1 = findings above baseline, 2 = tool/baseline error.
Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import datetime
import json
import platform
import re
import subprocess
import sys
import tempfile
from importlib import metadata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "ci" / "quality-baseline.json"
TARGET = "blncs/"

# ---------------------------------------------------------------------------
# Tool runners: each returns (counts, info) where counts maps a finding
# category to the number of findings, and info carries extra context lines.
# The tool invocations mirror the previous hard-gate steps in
# .github/workflows/production-ci-cd.yml exactly.
# ---------------------------------------------------------------------------

_FLAKE8_LINE = re.compile(r":\d+:\d+: ([A-Z][0-9]+) ")


def run_flake8() -> tuple[dict[str, int], list[str]]:
    proc = subprocess.run(
        [
            sys.executable, "-m", "flake8", TARGET,
            "--max-line-length=120", "--ignore=E203,W503",
        ],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"flake8 exited with {proc.returncode}:\n{proc.stderr}")
    counts: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        m = _FLAKE8_LINE.search(line)
        if m:
            counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return counts, []


_MYPY_ERROR = re.compile(r": error: ")
_MYPY_CODE = re.compile(r"\[([a-z0-9-]+)\]\s*$")


def run_mypy() -> tuple[dict[str, int], list[str]]:
    proc = subprocess.run(
        [sys.executable, "-m", "mypy", TARGET, "--ignore-missing-imports"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"mypy exited with {proc.returncode}:\n{proc.stderr}")
    counts: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        if not _MYPY_ERROR.search(line):
            continue
        m = _MYPY_CODE.search(line)
        code = m.group(1) if m else "no-code"
        counts[code] = counts.get(code, 0) + 1
    return counts, []


# The previous hard gate was `bandit -r blncs/ -ll`, which fails on any
# finding of severity MEDIUM or HIGH.  The baseline therefore covers exactly
# that set, keyed by "<test_id>:<severity>" so that a finding escalating in
# severity also counts as new.  LOW findings are reported for information
# only, exactly as before (they never failed the -ll gate).
_BANDIT_GATED_SEVERITIES = ("MEDIUM", "HIGH")


def run_bandit() -> tuple[dict[str, int], list[str]]:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as tmp:
        report_path = Path(tmp.name)
    try:
        subprocess.run(
            [
                sys.executable, "-m", "bandit", "-r", TARGET,
                "-f", "json", "-o", str(report_path),
            ],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"bandit did not produce a JSON report: {exc}")
    finally:
        report_path.unlink(missing_ok=True)

    counts: dict[str, int] = {}
    low = 0
    for result in report.get("results", []):
        severity = result.get("issue_severity", "")
        if severity in _BANDIT_GATED_SEVERITIES:
            key = f"{result.get('test_id', '?')}:{severity}"
            counts[key] = counts.get(key, 0) + 1
        elif severity == "LOW":
            low += 1
    info = [
        f"info: {low} LOW-severity bandit findings are not gated "
        "(the previous -ll gate ignored them too)."
    ]
    return counts, info


RUNNERS = {
    "flake8": run_flake8,
    "mypy": run_mypy,
    "bandit": run_bandit,
}


# ---------------------------------------------------------------------------
# CodeQL: the findings live on GitHub's side, so this gate cannot run its
# tool locally.  The production workflow fetches the open alerts for main
# from the code-scanning API and hands the payload to this script; the
# aggregation below is a pure function of that payload so it can be
# exercised offline against a saved sample.  Counts are keyed by the
# alerts' security severity level -- the same buckets the GitHub code
# scanning view shows (critical / high / medium / low).
# ---------------------------------------------------------------------------


def aggregate_codeql_alerts(payload) -> dict[str, int]:
    """Count open alerts by security severity level.

    ``payload`` is the decoded code-scanning API response: a list of
    alert objects, or -- when fetched with ``gh api --paginate
    --slurp`` -- a list of per-page lists.  Only ``state == "open"``
    alerts are counted (the workflow already filters on the API side;
    this is a second, defensive pass).  An alert without a security
    severity level is counted under "unknown", which is absent from the
    baseline and therefore fails the gate loudly instead of being
    silently dropped.
    """
    if isinstance(payload, dict):
        payload = payload.get("alerts", [])
    counts: dict[str, int] = {}
    if not isinstance(payload, list):
        return counts
    for page in payload:
        alerts = page if isinstance(page, list) else [page]
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            if alert.get("state", "open") != "open":
                continue
            rule = alert.get("rule") or {}
            level = rule.get("security_severity_level") or "unknown"
            counts[level] = counts.get(level, 0) + 1
    return counts


COMMAND_DESCRIPTIONS = {
    "flake8": "flake8 blncs/ --max-line-length=120 --ignore=E203,W503",
    "mypy": "mypy blncs/ --ignore-missing-imports",
    "bandit": "bandit -r blncs/ (severity MEDIUM/HIGH; mirrors `bandit -r blncs/ -ll`)",
}


def tool_versions() -> dict[str, str]:
    versions = {}
    for name in RUNNERS:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = "unknown"
    # Finding counts (mypy's especially) also depend on the interpreter
    # version, so record it alongside the tool versions: the baseline is
    # only comparable when measured in the recorded environment.
    versions["python"] = platform.python_version()
    return versions


def load_baseline() -> dict:
    try:
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except OSError:
        raise RuntimeError(f"baseline file not found: {BASELINE_PATH}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"baseline file is not valid JSON: {exc}")


def compare(baseline: dict[str, int], current: dict[str, int]):
    """Return (failures, decreases) as lists of human-readable lines."""
    failures = []
    decreases = []
    for key in sorted(set(baseline) | set(current)):
        base = baseline.get(key, 0)
        cur = current.get(key, 0)
        if cur > base:
            if base == 0:
                failures.append(f"  {key}: NEW category with {cur} finding(s)")
            else:
                failures.append(f"  {key}: {base} -> {cur} (+{cur - base})")
        elif cur < base:
            decreases.append(f"  {key}: {base} -> {cur} (-{base - cur})")
    return failures, decreases


def _check_counts(
    name: str,
    counts: dict[str, int],
    info: list[str],
    baseline_doc: dict,
    ratchet_hint: str,
) -> bool:
    total = sum(counts.values())
    gate_doc = baseline_doc.get("gates", {}).get(name)
    if gate_doc is None:
        print(f"[{name}] ERROR: no baseline recorded for this gate.")
        return False
    base_counts = gate_doc.get("counts", {})
    base_total = sum(base_counts.values())
    print(f"[{name}] findings: {total} (baseline: {base_total})")
    for line in info:
        print(f"[{name}] {line}")
    failures, decreases = compare(base_counts, counts)
    if decreases:
        print(f"[{name}] debt decreased -- {ratchet_hint}")
        for line in decreases:
            print(line)
    if failures:
        print(f"[{name}] FAIL: findings above the baseline:")
        for line in failures:
            print(line)
        print(f"[{name}] Fix the new findings. Raising the baseline requires "
              "an explicit justification in the PR (see docs/QUALITY_GATES.md).")
        return False
    print(f"[{name}] PASS")
    return True


def check_gate(name: str, baseline_doc: dict) -> bool:
    counts, info = RUNNERS[name]()
    return _check_counts(
        name, counts, info, baseline_doc,
        f"please ratchet the baseline down "
        f"with: python scripts/quality_gate.py {name} --update",
    )


def check_codeql_gate(baseline_doc: dict, alerts_path: str) -> bool:
    try:
        payload = json.loads(Path(alerts_path).read_text(encoding="utf-8"))
    except OSError:
        raise RuntimeError(f"alerts payload not found: {alerts_path}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"alerts payload is not valid JSON: {exc}")
    counts = aggregate_codeql_alerts(payload)
    info = [
        "info: counts are the open CodeQL alerts for main from the "
        "latest completed analysis at fetch time; alerts introduced "
        "by the current push are picked up by the next run "
        "(see docs/QUALITY_GATES.md)."
    ]
    return _check_counts(
        "codeql", counts, info, baseline_doc,
        "please ratchet the baseline down by lowering the codeql "
        "counts in ci/quality-baseline.json (see docs/QUALITY_GATES.md)",
    )


def update_baseline(names: list[str], baseline_doc: dict | None) -> None:
    doc = baseline_doc or {"version": 1, "gates": {}}
    doc["generated_on"] = datetime.date.today().isoformat()
    doc["tool_versions"] = tool_versions()
    for name in names:
        counts, _info = RUNNERS[name]()
        doc["gates"][name] = {
            "command": COMMAND_DESCRIPTIONS[name],
            "total": sum(counts.values()),
            "counts": dict(sorted(counts.items())),
        }
        print(f"[{name}] baseline updated: {sum(counts.values())} findings "
              f"in {len(counts)} categories")
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"Baseline written to {BASELINE_PATH.relative_to(REPO_ROOT)}")
    print("Review the diff before committing: decreases are the ratchet "
          "working; increases need an explicit justification.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "gates", nargs="*", default=["all"],
        help="gates to run: flake8, mypy, bandit, or all (default: all)",
    )
    parser.add_argument(
        "--update", action="store_true",
        help="regenerate the baseline from the current findings and exit",
    )
    parser.add_argument(
        "--alerts", metavar="PATH",
        help="code-scanning alerts JSON payload (required for the "
             "codeql gate; fetched from the GitHub API by the workflow)",
    )
    args = parser.parse_args(argv)

    names = list(RUNNERS) if "all" in args.gates else args.gates
    unknown = [n for n in names if n not in RUNNERS and n != "codeql"]
    if unknown:
        print(f"unknown gate(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    if args.update and "codeql" in names:
        print("ERROR: the codeql baseline cannot be regenerated locally; "
              "lower the counts in ci/quality-baseline.json from the "
              "GitHub code-scanning view instead "
              "(see docs/QUALITY_GATES.md).", file=sys.stderr)
        return 2

    try:
        baseline_doc = None if args.update and not BASELINE_PATH.exists() \
            else load_baseline()
    except RuntimeError as exc:
        if not args.update:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        baseline_doc = None

    try:
        if args.update:
            update_baseline(names, baseline_doc)
            return 0
        ok = True
        for name in names:
            if name == "codeql":
                if not args.alerts:
                    print("ERROR: the codeql gate requires --alerts PATH "
                          "(a code-scanning alerts payload fetched from "
                          "the GitHub API)", file=sys.stderr)
                    return 2
                if not check_codeql_gate(baseline_doc, args.alerts):
                    ok = False
            elif not check_gate(name, baseline_doc):
                ok = False
        return 0 if ok else 1
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
