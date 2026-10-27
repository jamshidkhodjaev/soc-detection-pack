# Validation status

Date: 27 October 2026

## Current milestone

All three planned Sigma rules have passed local parsing, synthetic fixture
evaluation, predicate-removal mutation checks, and Splunk SPL generation.

| Check | IIS spawning a shell | Office spawning PowerShell | Scheduled-task creation |
| --- | --- | --- | --- |
| pySigma parsing | Passed | Passed | Passed |
| Positive fixtures | 2/2 passed | 2/2 passed | 2/2 passed |
| Negative boundary fixtures | 2/2 passed | 2/2 passed | 4/4 passed |
| Incomplete-event fixture | 1/1 passed | 1/1 passed | 1/1 passed |
| Predicate-removal mutations | 2/2 detected | 2/2 detected | 3/3 detected |
| SPL generation using Sysmon pipeline | Completed | Completed | Completed |
| Execution in Splunk | Not tested | Not tested | Not tested |

Totals:

- Three implemented rules.
- 17 fixture expectations passed.
- Seven predicate-removal mutations detected.
- Three generated SPL queries.

These are local validation results. They do not establish real-world
detection accuracy or successful execution of the generated SPL.

## IIS rule

Rule: rules/iis_worker_spawning_shell.yml
Manifest: tests/iis_manifest.json
Query: converted/iis_worker_spawning_shell.spl

Validated fixture outcomes:

- IIS spawning CMD: match.
- Explorer spawning CMD: no match.
- IIS spawning PowerShell: match.
- IIS spawning Notepad: no match.
- Missing ParentImage: no match, without a crash.

Fixtures detected removal of either parent or child predicate.

## Office rule

Rule: rules/office_spawning_powershell.yml
Manifest: tests/office_manifest.json
Query: converted/office_spawning_powershell.spl

Validated fixture outcomes:

- Word spawning Windows PowerShell: match.
- Excel spawning PowerShell 7: match.
- Explorer spawning Windows PowerShell: no match.
- Word spawning Notepad: no match.
- Missing Image: no match, without a crash.

Fixtures detected removal of either parent or child predicate.

## Scheduled-task rule

Rule: rules/schtasks_creation_suspicious_path.yml
Manifest: tests/schtasks_manifest.json
Query: converted/schtasks_creation_suspicious_path.spl

Validated fixture outcomes:

- Creation command referencing AppData: match.
- Creation command referencing Temp with uppercase executable and switches: match.
- Creation command without AppData or Temp: no match.
- Task-change command missing /create: no match.
- XML-based creation command missing /tr: no match.
- Matching command text in a cmd.exe event: no match.
- Missing Image: no match, without a crash.

Fixtures detected removal of each selection entry:

- Image|endswith
- CommandLine|contains|all
- CommandLine|contains

## Shared tooling

The evaluator reads the actual Sigma YAML selection.

Supported modifiers:

- FIELD|endswith: at least one literal suffix.
- FIELD|contains: at least one literal substring.
- FIELD|contains|all: every listed literal substring.

All selection entries are joined by AND.
Comparisons are case-insensitive using Python casefold.
Unsupported syntax causes an error.

The mutation script accepts a manifest path. Without an argument,
it defaults to tests/iis_manifest.json.

Each mutation run first requires the original rule to pass.
It then removes each selection entry from a separate in-memory copy.
The original YAML files are not modified.

Execution errors are not counted as detected mutations.
Dependency versions are recorded in requirements.lock.txt.

After extending the evaluator and mutation script, regression checks
passed for both earlier rules.

## Reproduction commands

Run from the repository root with the virtual environment active.

### Parsing

```bash
python scripts/parse_rule.py rules/iis_worker_spawning_shell.yml
python scripts/parse_rule.py rules/office_spawning_powershell.yml
python scripts/parse_rule.py rules/schtasks_creation_suspicious_path.yml
```

### Fixture evaluation

```bash
python scripts/evaluate.py tests/iis_manifest.json
python scripts/evaluate.py tests/office_manifest.json
python scripts/evaluate.py tests/schtasks_manifest.json
```

Expected summaries: 5/5, 5/5, and 7/7 fixture expectations passed.

### Mutation checks

```bash
python scripts/mutation_check.py tests/iis_manifest.json
python scripts/mutation_check.py tests/office_manifest.json
python scripts/mutation_check.py tests/schtasks_manifest.json
```

Expected summaries: 2/2, 2/2, and 3/3 mutations detected.

### SPL generation

```bash
sigma convert -t splunk -p sysmon -f default -o converted/iis_worker_spawning_shell.spl rules/iis_worker_spawning_shell.yml
sigma convert -t splunk -p sysmon -f default -o converted/office_spawning_powershell.spl rules/office_spawning_powershell.yml
sigma convert -t splunk -p sysmon -f default -o converted/schtasks_creation_suspicious_path.spl rules/schtasks_creation_suspicious_path.yml
```

Expected: each conversion completes without errors and produces a nonempty query.

## GitHub Actions status

Workflow: .github/workflows/checks.yml
Workflow run: https://github.com/jamshidkhodjaev/soc-detection-pack/actions/runs/40415739345

The workflow has been authored and is configured to:

- Install recorded dependencies and check package compatibility.
- Parse all three rules.
- Evaluate all three fixture manifests.
- Run all predicate-removal mutation checks.
- Regenerate SPL into temporary files.
- Compare regenerated queries with committed queries using exact text comparison.

Successful GitHub Actions runs were reported for:

- dde6bc3: initial automated validation.
- 898bed8: validation after upgrading actions/setup-python to v6.

For commit 898bed8, the workflow completed successfully in 16 seconds;
the validate job completed in 13 seconds.

The workflow checks dependency compatibility, parses all three rules,
evaluates 17 fixture expectations, detects seven predicate-removal
mutations, and regenerates and compares all three SPL queries.

The earlier Node.js deprecation warning was absent from the second run.
An informational ubuntu-latest migration notice remained.

These results demonstrate reproduction in the configured GitHub runner.
A separate clean-checkout verification on macOS also passed, as recorded below.

## Limitations

- All fixtures are synthetic.
- The evaluator supports only the documented restricted Sigma subset.
- Passing fixtures does not establish precision, recall, or operational effectiveness.
- Mutation checks cover specific predicate-removal mistakes, not every possible defect.
- Generated SPL has not been executed in Splunk.
- Missing-field non-matches do not establish that events are safe.
- The IIS pwsh.exe branch has no dedicated positive fixture.
- Office PowerPoint and Outlook branches have no dedicated positive fixtures.
- Scheduled-task matching uses substrings rather than parsed arguments.
- Directory references may occur outside the actual scheduled-task action.
- Scheduled-task process creation does not establish successful task registration.

## Clean-checkout verification

Date: 27 October 2026
Platform: macOS
Verified commit: 896bdd8b2a0f61e3963edbe084ad17e0e28a6a22

The repository was cloned from GitHub into a separate temporary directory.
A new virtual environment was created and dependencies were installed
from requirements.lock.txt.

Results:

- pip check reported no broken requirements.
- All three rules passed pySigma parsing.
- All 17 fixture expectations passed.
- All seven predicate-removal mutations were detected.
- All three SPL queries were regenerated successfully.
- git diff --exit-code -- converted/ reported no differences.
- git status --short produced no output.

This verifies reproduction of the committed implementation in a fresh
local environment. Generated SPL remains untested in Splunk.

## Remaining work

## Remaining work

- Review the investigation summary in docs/investigation.md.
- Reconcile README and other documentation with the verified results.
- Commit and push the investigation and verification documentation.
- Confirm CI passes for the final release candidate.
- Prepare the v0.1.0 release.

The full Detection Pack release gate has not yet been met.