# Validation status

Evidence reviewed: 27 October 2026. This is the authoritative record for
validation counts and detailed evidence. All rules remain experimental.

## Historical v0.1.0 release and baseline

The v0.1.0 tag was verified at
`0a64078da75337dd85173a533224d665940e6c01`, the baseline for this maintenance work.
GitHub REST API inspection on 27 October 2026 confirmed the
[v0.1.0 experimental pre-release](https://github.com/jamshidkhodjaev/soc-detection-pack/releases/tag/v0.1.0)
with `draft: false`, `prerelease: true`, and publication at `2026-10-27T00:40:02Z`.
Release-note assertions are not independent proof of validation results.

For current published versions and CI results, consult
[GitHub Releases](https://github.com/jamshidkhodjaev/soc-detection-pack/releases)
and [GitHub Actions](https://github.com/jamshidkhodjaev/soc-detection-pack/actions).

## Re-established baseline

Local checks on 27 October 2026 reproduced the following baseline results before
the maintenance fixtures were added:

| Check | IIS | Office | Scheduled task | Total |
| --- | --- | --- | --- | --- |
| Synthetic expectations | 5/5 | 5/5 | 7/7 | 17/17 |
| Predicate removals detected | 2/2 | 2/2 | 3/3 | 7/7 |
| Individual list-value removals detected | 2/3 | 4/6 | 4/4 | 10/13 |

The uncovered values were IIS `Image|endswith` value `\pwsh.exe`, and Office
`ParentImage|endswith` values `\POWERPNT.EXE` and `\OUTLOOK.EXE`.
These results were measured with an in-memory baseline probe and reproduced by
the expanded mutation checker before adding the new fixtures.

## Local maintenance validation — 27 October 2026

The results below describe a dated local run against the maintenance working tree,
including the scheduled-task additions and conversion wrapper. They are not a CI
result and do not validate a future commit. Each release candidate requires checks
against its exact commit.

Environment: macOS, Python 3.13.0, isolated virtual environment outside the
repository, with dependencies installed from `requirements.lock.txt`. Installed
versions matched the lockfile, and `pip check` reported no broken requirements.
All listed local checks completed successfully.

| Check | IIS | Office | Scheduled task | Total |
| --- | --- | --- | --- | --- |
| Synthetic fixture expectations | 6/6 | 7/7 | 19/19 | 32/32 |
| Positive cases | 3/3 | 4/4 | 4/4 | 11/11 |
| Negative boundary cases | 2/2 | 2/2 | 14/14 | 18/18 |
| Incomplete-event cases | 1/1 | 1/1 | 1/1 | 3/3 |
| Predicate removals detected | 2/2 | 2/2 | 3/3 | 7/7 |
| Individual list-value removals detected | 3/3 | 6/6 | 6/6 | 15/15 |
| pySigma parsing | Passed | Passed | Passed | 3/3 |
| SPL regeneration and exact diff | Passed | Passed | Passed after regeneration | 3/3 |
| Execution in Splunk | Not tested | Not tested | Not tested | Not tested |

The standard-library unittest suite passed all 16 tests, including parameterized
subcases for duplicate YAML keys through the evaluator and mutation CLI loading
paths; unsupported modifiers and wildcard literals; empty manifests and fixture
files; missing routing fields; non-integer EventID (including booleans); missing
detection-field non-matches; case-insensitive endswith, contains, and contains|all;
expectation-mismatch exit behavior; the original-rule gate; and mutation errors
not counting as detection.

Of these 16 tests, four conversion regressions verify duplicate-key rejection before
converter invocation (with existing and absent destinations), preservation of
existing output after a converter writes partial data and fails, successful
conversion with the real locked converter, and conversion of the validated
snapshot even when the original source changes before converter invocation.

New synthetic positive fixtures, preserving all prior cases:

- `syn-iis-003`: IIS directly spawning pwsh.exe.
- `syn-office-003`: POWERPNT.EXE directly spawning powershell.exe.
- `syn-office-004`: OUTLOOK.EXE directly spawning powershell.exe.
- `syn-task-003`: literal `%APPDATA%` in the observed command line.
- `syn-task-004`: literal `%temp%` in the observed command line (case-insensitive).

Each has one JSONL record, a unique identifier, required context and routing
fields, and `synthetic: true`.

The focused scheduled-task pass adds ten negative boundary fixtures
(`syn-task-boundary-001` through `syn-task-boundary-010`): missing `/create`,
missing `/tr`, wrong executable, Tempest, Templates, AppDatabase, bare `C:\Temp`,
`%APPDATA_BACKUP%`, `%TEMP_BACKUP%`, and hyphen-only switches. All prior cases
are preserved. The existing mutation checker automatically enumerates the two
new list values; both removals are detected by their dedicated positive fixtures.

Among the rule detection selections, only the scheduled-task path/reference list changes. It adds complete
`%APPDATA%` and `%TEMP%` tokens while retaining `\AppData\` and `\Temp\`.
The executable and both slash-switch requirements remain mandatory. Percent signs
are ordinary literal characters in the supported contains operation, requiring no
additional evaluator or mutation-code changes for this extension. The configured
CI checks use the updated manifest and enumerate the expanded list.

Scheduled-task SPL was regenerated with the locked Sigma CLI, Splunk backend,
and Sysmon pipeline. Its path/reference OR list now includes `*%APPDATA%*` and
`*%TEMP%*`; the other predicates are preserved. Independent temporary regeneration
then matched all three tracked SPL files exactly. IIS and Office SPL are unchanged.
No manual SPL edits were made.

These are literal-string tests only. Environment variables may be expanded before
process-creation telemetry is recorded; no prevalence estimate or Windows behavior
is established by the fixtures. No real Windows execution or SIEM validation was
performed. See [scheduled-task context](scheduled-task-context.md) for Microsoft
references, complete boundary coverage, and the excluded, unverified hyphen-switch
extension. A reference anywhere in the command line need not be the `/tr` target.

## Mutation and loading contract

The original rule must pass before mutation testing. Each selection predicate
is removed from a separate in-memory copy. Each individual element of supported
selection lists with at least two values is then removed from a separate copy.
Scalar values and singleton lists have no individual-value mutation: removal
would leave an invalid empty predicate. OR lists and contains|all lists are both
tested. Totals are reported separately for predicates and list values.

Only an actual expectation mismatch (evaluator return code 1) counts as detected.
Exceptions and invalid mutated rules are reported as errors and cannot pass the
mutation gate. Undetected mutations return 1; mutation errors return 2. Rule files
are never changed by mutation testing. The evaluator and mutation checker use
the same strict YAML loader; the pySigma parsing entry point also performs this
strict duplicate-key check before parsing.

The supported standalone and CI conversion path is `scripts/convert_rule.py`.
It copies the input bytes once to a temporary snapshot, validates that snapshot
with the shared `load_rule`, and invokes `python -m sigma.cli.main` without a shell.
The backend remains `splunk`, pipeline `sysmon`, and format `default`. Conversion
uses the same Python environment as the wrapper and unchanged locked dependencies.
Output is written temporarily on the destination filesystem and replaces the
requested file only after successful conversion with a nonempty result. Validation
failure, conversion failure, or missing/empty converter output cannot overwrite
an existing artifact. Direct `sigma convert` bypasses the strict loading gate
and is no longer the documented or CI-supported path.

## Historical v0.1.0 GitHub Actions evidence

GitHub REST API inspection on 27 October 2026 established these completed, successful
runs of **Detection Pack Checks**, `.github/workflows/checks.yml`:

| Exact commit SHA | Run | Result |
| --- | --- | --- |
| `896bdd8b2a0f61e3963edbe084ad17e0e28a6a22` | [40415739345](https://github.com/jamshidkhodjaev/soc-detection-pack/actions/runs/40415739345) | success |
| `0a64078da75337dd85173a533224d665940e6c01` | [40427245738](https://github.com/jamshidkhodjaev/soc-detection-pack/actions/runs/40427245738) | success |
| `0a64078da75337dd85173a533224d665940e6c01` | [40427581847](https://github.com/jamshidkhodjaev/soc-detection-pack/actions/runs/40427581847) | success |

The previously recorded `898bed8` reference was invalid. Run `40415739345`
identifies the exact `head_sha` as `896bdd8b2a0f61e3963edbe084ad17e0e28a6a22`,
the setup-python runtime update.

These API records establish workflow identity, commit, completion, and result
for the historical commits only. Job logs were not independently audited. The
maintenance fixture and mutation counts above come from local executions, not
release notes or inferred log contents. No remote CI result for the maintenance
changes is asserted by this record.

The maintenance CI configuration runs regression tests, pySigma parsing, all fixture manifests, expanded
mutation checks, and SPL regeneration with exact comparison, using the lockfile.

## Recorded historical claims

Previous documentation reported successful CI at `dde6bc3`. That specific run
was not independently checked in this maintenance review.

It also recorded a clean-checkout verification on macOS on 27 October 2026 at
`896bdd8b2a0f61e3963edbe084ad17e0e28a6a22`: a separate clone and fresh environment,
`pip check`, parsing of all three rules, 17 passing fixture expectations, seven
detected predicate mutations, regenerated SPL with no diff, and a clean status.
This is retained as a historical report, not as a newly observed clean-checkout
run. The dated maintenance validation used the maintenance working tree and an isolated
environment; it does not establish clean-checkout reproduction of a release
candidate.

## Reproduction

From the repository root, activate an isolated environment and install the
unchanged lockfile. Then run:

```bash
python -m pip install -r requirements.lock.txt
python -m pip check
python -m unittest discover -s tests -p 'test_*.py' -v
```

Run all manifests and parsers; fail immediately on any unsuccessful command:

```bash
set -euo pipefail
for manifest in tests/*_manifest.json; do
  python scripts/evaluate.py "$manifest"
  python scripts/mutation_check.py "$manifest"
done
output_dir=$(mktemp -d)
for rule in rules/*.yml; do
  python scripts/parse_rule.py "$rule"
  name=$(basename "$rule" .yml)
  python scripts/convert_rule.py -o "$output_dir/$name.spl" "$rule"
  test -s "$output_dir/$name.spl"
  diff -u "converted/$name.spl" "$output_dir/$name.spl"
done
```

## ATT&CK metadata review

Mappings were checked against MITRE's authoritative technique pages:

- IIS: [T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/),
  a contextual relationship to possible server-side command execution. Process
  ancestry alone does not prove a web shell exists. No PowerShell-specific tag
  is applied across the IIS rule's cmd.exe branch.
- Office: [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/),
  related execution behavior, which may also be approved automation.
- Scheduled tasks: [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/),
  related execution, persistence, and privilege-escalation context. A launch of
  schtasks.exe does not prove task registration or execution.

Tags provide investigative context. No rule match proves that a mapped
adversarial technique occurred.

## Limitations

All fixtures are synthetic. These checks do not establish precision, recall,
production readiness, or operational effectiveness. The evaluator supports only
the documented restricted Sigma subset and does not execute SPL. Mutation checks
cover specific removals, not every defect. Missing-field non-matches do not
establish safety. Generated queries have not been executed in Splunk.

Scheduled-task matching remains substring-based: it does not parse arguments,
expand variables, resolve paths, or establish successful task registration.
Directory references can appear outside the actual task action.

## Remaining work

For each maintenance release candidate:

- Review the changes and synthetic investigation through the normal review process.
- Verify CI for the exact candidate commit and reproduce it from a clean checkout.
- Prepare release notes preserving the experimental and synthetic-only limitations.
- Preserve the existing v0.1.0 tag and pre-release.
