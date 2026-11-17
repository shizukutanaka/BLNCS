# Quality Gates: Baseline (Ratchet) Design

## Why this exists

Three checks in the Production CI (`production-ci-cd.yml`, job
`code-quality`) were written as all-or-nothing gates over code with a large
amount of pre-existing debt:

| Gate | Command (unchanged) | Findings on main (measured 2026-11-17) |
| --- | --- | --- |
| flake8 (full) | `flake8 blncs/ --max-line-length=120 --ignore=E203,W503` | 880 |
| mypy | `mypy blncs/ --ignore-missing-imports` | 3,621 errors |
| bandit | `bandit -r blncs/ -ll` (severity MEDIUM and HIGH) | 31 (all MEDIUM; HIGH is 0) |

Demanding "zero findings" from several thousand legacy findings keeps the
job permanently red. A gate that is always red is ignored by everyone and
stops protecting anything — it has negative value. At the same time,
switching the checks to advisory (`|| true`) would throw away the
protection entirely.

The compromise implemented here is a **baseline freeze (ratchet)**:

- The current findings are counted **per category** and frozen in
  [`ci/quality-baseline.json`](../ci/quality-baseline.json).
- CI re-runs the same tools with the same arguments and compares counts.
- **Any category that grows — or any new category that appears — fails.**
  New findings still turn CI red, exactly as a zero-tolerance gate would
  treat them.
- Counts at or below the baseline pass. When a count drops, the gate
  passes and prints a notice asking to ratchet the baseline down, so the
  recorded debt can only shrink over time.

Per-category comparison (instead of a single total) matters: with a single
total, one new `F401` could hide behind one removed `E501`. With
per-category counts there is no netting.

For bandit, categories are keyed by `<test_id>:<severity>` over the
MEDIUM/HIGH set — the exact set the old `bandit -r blncs/ -ll` step failed
on. LOW findings (170 today) are printed for information only; they never
failed the old gate and they do not fail this one. A finding escalating
from LOW to MEDIUM creates a key that is not in the baseline and fails.

## What did *not* change

The redesign only changes how the three debt-carrying checks are judged.
Everything that was green stays exactly as it was:

- The test suites (ci-cd.yml and production `test` job).
- The critical flake8 gate (`--select=E9,F63,F7,F82`) in ci-cd.yml.
- `black --check`, `isort --check-only`, `pylint --fail-under=8.0`
  (measured 8.50/10 on 2026-11-17) in the production code-quality job.
- The bandit High count is 0 after the 2026-11-17 security triage, and
  the baseline makes any new MEDIUM/HIGH finding fail, so the security
  posture enforced by CI is unchanged.

## How it works

`scripts/quality_gate.py` (standard library only) runs one or more gates:

```console
$ python scripts/quality_gate.py all
[flake8] findings: 880 (baseline: 880)
[flake8] PASS
[mypy] findings: 3621 (baseline: 3621)
[mypy] PASS
[bandit] findings: 31 (baseline: 31)
[bandit] info: 170 LOW-severity bandit findings are not gated (the previous -ll gate ignored them too).
[bandit] PASS
```

Exit codes: `0` pass, `1` findings above baseline, `2` tool or baseline
error (a broken tool never silently passes).

## Measurement environment

The counts are only comparable when measured in the environment the
baseline was frozen in. That environment is recorded in `tool_versions`
in the baseline JSON: **Python 3.12 (3.12.3), flake8 7.5.0, mypy 2.4.1,
bandit 1.9.4**.

This is not pedantry — the counts are genuinely environment-sensitive.
With identical code and identical tool versions, running mypy under
Python 3.11 instead of 3.12 reports 3,624 errors with a different
per-category mix, and the first CI run of this gate (Python 3.11,
unpinned tool installs) reported 3,626 and failed, even though the
change under review touched no file under `blncs/`. Under the recorded
environment, a fresh install reproduces 880 / 3,621 / 31 exactly.

Therefore:

- The production `code-quality` job is pinned to the recorded
  environment: its Python is 3.12 and the three gated tools are
  installed with `==` pins matching `tool_versions`. (The pins satisfy
  the `>=` floors in `requirements-dev.txt`, so the requirements
  installs in the same step do not move them.)
- Regenerate the baseline only in the recorded environment. If the
  environment is deliberately upgraded (Python or tool major version),
  regenerate the baseline in the new environment, let `--update` record
  the new versions, update the pins in `production-ci-cd.yml` to match,
  and state the environment change as the justification in the PR.

## Updating the baseline

Ratcheting down (the normal case, after fixing findings):

```console
$ python scripts/quality_gate.py all --update
$ git diff ci/quality-baseline.json   # review: decreases only
```

Commit the regenerated baseline **in the same PR** that reduced the
findings. Reviewers check the baseline diff like any other change:

- **Decreases** are the ratchet working. Expected and welcome.
- **Increases** re-open the gate to new debt. They require an explicit
  justification in the PR description (for example: a tool major-version
  upgrade changed what the tool reports, with no code change). An
  unjustified increase should be rejected in review — fix the findings
  instead.

Counts are tool-version sensitive: the baseline records the tool versions
it was generated with (`tool_versions` in the JSON). For reference, an
earlier count of mypy findings was 3,761; measured with mypy 2.4.1 on
2026-11-17 it is 3,621. When a tool upgrade shifts counts without any
code change, regenerate the baseline, record the new tool version, and
say so in the PR.

## How the debt is expected to shrink

1. Ordinary PRs may fix findings opportunistically; the gate notice
   reminds the author to ratchet the baseline down in the same PR.
2. Dedicated debt-reduction PRs pick one category (e.g. flake8 `F401`,
   598 findings) and lower it in bulk.
3. When a category reaches zero, `--update` drops it from the baseline;
   any later recurrence is a *new* category and fails immediately.
4. The end state is an empty baseline, at which point the gates are
   zero-tolerance again — reached incrementally instead of by decree.

## CodeQL (baseline gate, API-based)

GitHub code scanning reported **79 open CodeQL alerts on main** (as of
2026-11-17: 0 critical, 30 high, 49 medium, 0 low; all Python). These
findings live on GitHub's side and cannot be counted from a local
checkout, so the CodeQL gate works differently from the three local
gates above while following the same ratchet rules:

- The `codeql-baseline` job in `production-ci-cd.yml` runs on every
  push to `main` (and on manual dispatch). It fetches the open alerts
  for main from the code-scanning API
  (`GET /repos/{owner}/{repo}/code-scanning/alerts` with `state=open`,
  `ref=refs/heads/main`, `tool_name=CodeQL`) using a read-only
  `security-events` permission, and
  `scripts/quality_gate.py codeql --alerts <payload>` counts them per
  security severity level and compares them against the `codeql` entry
  in `ci/quality-baseline.json`. Any severity above its baseline fails
  the job; decreases pass and print a ratchet notice, exactly like the
  local gates.
- On pull requests, the CodeQL check itself already behaves like a
  baseline gate: it passes when the PR introduces no *new* alerts
  (observed in PR #27, where the check passed with "no new alerts"
  while 81 alerts existed on main). That part needed no redesign; the
  API gate above covers the main-branch total, which the PR check does
  not.

**Timing caveat (a property of code scanning, not a weaker gate):**
analysis results are processed asynchronously, so the counts a run
fetches are those of the latest *completed* analysis at that moment.
Alerts introduced by a push are therefore detected by the *next* run's
gate at the latest, not necessarily by the run the push itself
triggered. Growth is caught a run late, never excused.

Updating the baseline: `--update` cannot regenerate the CodeQL counts
locally. After fixing alerts, read the new totals from the
code-scanning view (Security tab) and lower the `codeql` counts in
`ci/quality-baseline.json` in the same PR. Increases follow the same
rule as every other gate: an explicit justification in the PR
description, or fix the findings instead.

## Deployment jobs are opt-in (`ENABLE_DEPLOY`)

BLNCS is provided as software only: the project does not operate (or
pay for) deployment infrastructure. The deploy chain in
`production-ci-cd.yml` -- `deploy-staging`, `performance-test`,
`deploy-production` and `rollback` -- therefore runs only when the
repository variable `ENABLE_DEPLOY` is set to `true`. Without it the
jobs are skipped and a push to main finishes green on the build; this
is deliberate, not a broken pipeline. (Before this change,
`deploy-staging` ran on every push to main and failed on the missing
AWS credentials, turning the whole run red.)

To deploy to your own AWS account:

1. Settings -> Secrets and variables -> Actions -> **Variables** tab
   -> New repository variable: name `ENABLE_DEPLOY`, value `true`.
2. On the **Secrets** tab of the same page, configure the credentials
   the jobs reference (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`,
   the `_PROD` pair for production, and `SLACK_WEBHOOK_URL` for the
   Slack notifications).

With the variable set, the jobs behave exactly as before: staging
deploys from `main`, production from `v*` tags, and `rollback` runs
when a production deployment fails.
