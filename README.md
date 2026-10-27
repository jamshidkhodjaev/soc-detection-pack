# SOC Detection Pack

Experimental SOC detection engineering portfolio project by Jamshid Khodjaev.

Three Sigma rules with documented hypotheses, synthetic event fixtures,
behavioral evaluation, predicate-removal mutation checks, and Splunk SPL generation.

Local validation completed:

- Three rules parsed with pySigma.
- 17 synthetic fixture expectations passed.
- Seven predicate-removal mutations detected.
- Three SPL queries generated using the Sysmon pipeline.

GitHub Actions passed for commit 898bed8. A separate clean-checkout
verification on macOS also passed; the tested commit is recorded in
docs/validation-status.md.

The synthetic investigation write-up is available in docs/investigation.md.
Final documentation review and the v0.1.0 release remain pending.

All fixtures are synthetic. Generated SPL has not been executed in Splunk.
No production readiness or measured detection accuracy is claimed.

## Detection scope

| Rule | Required behavior |
| --- | --- |
| IIS spawning a shell | w3wp.exe directly creates cmd.exe, powershell.exe, or pwsh.exe |
| Office spawning PowerShell | Word, Excel, PowerPoint, or Outlook directly creates powershell.exe or pwsh.exe |
| Scheduled-task creation referencing AppData or Temp | schtasks.exe command line contains /create, /tr, and an AppData or Temp directory reference |

Matches are investigation leads, not proof of compromise.
Approved applications, installers, or business automation may also match.

The scheduled-task rule uses substring matching. It does not parse arguments,
establish the actual task action, or confirm successful task registration.

## Validation status

Local validation on macOS, 26 October 2026:

| Check | IIS | Office | Scheduled task |
| --- | --- | --- | --- |
| pySigma parsing | Passed | Passed | Passed |
| Fixture expectations | 5/5 passed | 5/5 passed | 7/7 passed |
| Predicate-removal mutations | 2/2 detected | 2/2 detected | 3/3 detected |
| SPL generation | Completed | Completed | Completed |
| Execution in Splunk | Not tested | Not tested | Not tested |

Project-wide status:

| Deliverable | Status |
| --- | --- |
| Three rules and local validation | Completed |
| GitHub Actions | Passed for commit 898bed8 |
| Investigation write-up | Draft completed; synthetic case |
| Clean-checkout reproduction | Passed on macOS; tested commit recorded in validation record |
| Tagged v0.1.0 release | Pending |

See [the validation record](docs/validation-status.md) for details.

## Repository structure

| Path | Purpose |
| --- | --- |
| rules/ | Experimental Sigma YAML rules |
| fixtures/ | Synthetic normalized JSONL events |
| tests/iis_manifest.json | IIS fixture expectations |
| tests/office_manifest.json | Office fixture expectations |
| tests/schtasks_manifest.json | Scheduled-task fixture expectations |
| scripts/parse_rule.py | pySigma parsing check |
| scripts/evaluate.py | Restricted local Sigma evaluator |
| scripts/mutation_check.py | Selection-predicate removal checks |
| converted/ | Generated Splunk SPL queries |
| docs/telemetry.md | IIS hypothesis and shared telemetry/evaluator contract |
| docs/powershell-context.md | Office hypothesis and validation |
| docs/scheduled-task-context.md | Scheduled-task hypothesis and validation |
| docs/validation-status.md | Results, limitations, and remaining work |
| .github/workflows/checks.yml | Automated validation workflow |
| requirements.in | Direct dependencies |
| requirements.lock.txt | Resolved dependency versions used locally |
| docs/investigation.md | Synthetic IIS investigation, alternative explanations, and evidence needed |

## Setup

Run commands from the repository root in macOS Terminal or VS Code's terminal.

Observed local validation used Python 3.13.0.

Check Python:

```bash
python3 --version
```

For a fresh setup, create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Skip creation if a working .venv already exists.
Activation applies separately to each terminal session.

Install recorded dependencies:

```bash
python -m pip install -r requirements.lock.txt
python -m pip check
```

Direct dependencies:

```text
sigma-cli
pysigma-backend-splunk
PyYAML
pysigma-pipeline-sysmon
```

Sigma CLI uses pySigma for parsing. The Splunk backend generates SPL,
the Sysmon pipeline supplies event mapping, and PyYAML loads rule YAML.

Clean-checkout reproduction passed on macOS; see docs/validation-status.md.
Do not commit virtual environments or Python bytecode caches.

## Input contract

The intended source model is Windows Sysmon Event ID 1: process creation.

Each current fixture contains one UTF-8 JSON object on one physical line
and carries "synthetic": true.

| Field | Meaning |
| --- | --- |
| event_id | Synthetic record identifier, distinct from the Windows event number |
| EventID | Numeric Windows event type; integer 1 is in scope |
| timestamp_utc | Event timestamp ending in Z |
| host | Source computer |
| product, category | Local routing metadata |
| Image | Child executable path |
| ParentImage | Direct parent executable path |
| CommandLine | Full process command line |
| User | Child-process security principal |

The IIS and Office rules require Image and ParentImage.
The scheduled-task rule requires Image and CommandLine.

The current fixture runner also requires nonempty CommandLine and User context.
Incomplete fixtures deliberately omit Image or ParentImage.

Expected outcomes are stored in manifests, separately from event inputs.

JSON escapes backslashes: `C:\\Windows` represents `C:\Windows` after parsing.

A real normalizer must establish the Sysmon provider/channel.
An event number alone does not identify its provider.

## Fixture coverage

### IIS rule

| Scenario | Expected match |
| --- | --- |
| IIS spawning CMD | true |
| Explorer spawning CMD | false |
| IIS spawning PowerShell | true |
| IIS spawning Notepad | false |
| CMD event missing ParentImage | false |

### Office rule

| Scenario | Expected match |
| --- | --- |
| Word spawning Windows PowerShell | true |
| Excel spawning PowerShell 7 | true |
| Explorer spawning Windows PowerShell | false |
| Word spawning Notepad | false |
| Word parent with Image missing | false |

### Scheduled-task rule

| Scenario | Expected match |
| --- | --- |
| Creation command referencing AppData | true |
| Creation command referencing Temp with uppercase executable and switches | true |
| Creation command without AppData or Temp | false |
| Task-change command missing /create | false |
| XML-based creation command missing /tr | false |
| Matching command text in a cmd.exe event | false |
| Image missing | false |

Negative cases test rule boundaries; a non-match does not establish safety.
Missing-field non-matches indicate insufficient data to satisfy the rule.

## Check A: parse the rules

```bash
python scripts/parse_rule.py rules/iis_worker_spawning_shell.yml
python scripts/parse_rule.py rules/office_spawning_powershell.yml
python scripts/parse_rule.py rules/schtasks_creation_suspicious_path.yml
```

Each command should report:

```text
PASS: pySigma parsed 1 rule (no fixture evaluation or SPL execution)
```

Parsing checks that pySigma understands each rule.
It does not establish behavioral correctness or complete official JSON Schema validation.

## Check B: evaluate fixtures

```bash
python scripts/evaluate.py tests/iis_manifest.json
python scripts/evaluate.py tests/office_manifest.json
python scripts/evaluate.py tests/schtasks_manifest.json
```

Expected summaries:

- IIS: 5/5 fixture expectations passed.
- Office: 5/5 fixture expectations passed.
- Scheduled task: 7/7 fixture expectations passed.

The evaluator reads the actual YAML selection.

Supported structure and modifiers:

- One nonempty selection mapping and condition: selection.
- AND between selection entries.
- FIELD|endswith: at least one literal suffix.
- FIELD|contains: at least one literal substring.
- FIELD|contains|all: every listed literal substring.
- Case-insensitive comparison using Python casefold.
- Missing or null referenced detection fields evaluate false.

Unsupported syntax, invalid inputs, and missing routing metadata cause errors.
Different product, category, or integer event-type values evaluate false.
The command-line evaluator rejects duplicate YAML mapping keys.

This is a restricted project evaluator, not a general Sigma engine.

| Exit code | Meaning |
| --- | --- |
| 0 | All fixture expectations passed |
| 1 | At least one fixture expectation failed |
| 2 | Invalid input, unsupported syntax, or another execution error |

## Check C: detect weakened rules

```bash
python scripts/mutation_check.py tests/iis_manifest.json
python scripts/mutation_check.py tests/office_manifest.json
python scripts/mutation_check.py tests/schtasks_manifest.json
```

Expected mutation summaries:

- IIS: 2/2 mutations detected.
- Office: 2/2 mutations detected.
- Scheduled task: 3/3 mutations detected.

The script first requires the original rule to pass.
It enumerates selection entries and removes each entry from a separate
in-memory copy. The original YAML files are not modified.

A mutation is detected when fixture expectations fail.
Execution errors do not count as detected mutations.

Without a manifest argument, the script defaults to tests/iis_manifest.json.

These checks catch specific predicate-removal mistakes.
They do not establish complete defect coverage.

## Check D: generate Splunk SPL

```bash
sigma convert -t splunk -p sysmon -f default -o converted/iis_worker_spawning_shell.spl rules/iis_worker_spawning_shell.yml
sigma convert -t splunk -p sysmon -f default -o converted/office_spawning_powershell.spl rules/office_spawning_powershell.yml
sigma convert -t splunk -p sysmon -f default -o converted/schtasks_creation_suspicious_path.spl rules/schtasks_creation_suspicious_path.yml
```

Each command should complete without errors and generate a nonempty query.

The Sysmon pipeline supplies EventID=1 and retains raw event fields.
Queries use raw Sysmon fields rather than Splunk CIM/tstats.

The table clause selects displayed fields; it adds no matching predicates.

No Splunk index is assumed. Deployment requires appropriate data scope,
provider/channel verification, field extraction, and testing in Splunk.

## GitHub Actions

Workflow: .github/workflows/checks.yml

Configured triggers:

- Push.
- Pull request.
- Manual workflow dispatch.

The workflow uses an Ubuntu runner with Python 3.13 to:

1. Install recorded dependencies and run pip check.
2. Parse all three rules.
3. Evaluate all fixture manifests.
4. Run predicate-removal mutation checks.
5. Regenerate SPL into temporary files.
6. Compare regenerated queries with committed queries.

The SPL comparison checks exact text, not semantic equivalence.
A formatting difference can therefore cause a failure requiring review.

The workflow passed for commit 898bed8; see docs/validation-status.md for the run link.

## What validation demonstrates

| Check | Demonstrates | Does not demonstrate |
| --- | --- | --- |
| Parsing | pySigma understands the rules | Correct matching behavior |
| Fixture evaluation | 17 expected synthetic outcomes | Real-world accuracy or SPL correctness |
| Mutation checks | Seven predicate removals are caught | Complete defect coverage |
| Conversion | SPL generation with the selected pipeline | Successful execution in Splunk |
| CI, once verified | Checks reproduce in the configured runner | Production effectiveness |

Parsing, fixture evaluation, mutation checking, and conversion are separate checks.
The local evaluator does not execute generated SPL.

## Limitations

- All event fixtures are synthetic.
- Approved application behavior or administrative automation can match.
- Renamed executables, indirect execution, and absent telemetry can prevent matching.
- The IIS pwsh.exe branch has no dedicated positive fixture.
- Office PowerPoint and Outlook branches have no dedicated positive fixtures.
- Scheduled-task detection uses substrings rather than parsed arguments.
- A directory reference may appear outside the actual scheduled-task action.
- Environment variables are not expanded and paths are not resolved.
- A matching process event does not confirm successful task registration.
- The fixtures do not establish precision, recall, or operational effectiveness.
- Generated queries have not been executed in Splunk.
- CI and macOS clean-checkout checks passed for the recorded commits; later changes require their own validation.
Investigate process ancestry, command lines, accounts, timing, related logs,
and approved business behavior before concluding that compromise occurred.

## Remaining work

- Review the synthetic investigation and documentation for consistency.
- Commit and push the investigation and verification evidence.
- Confirm CI passes for the final release candidate.
- Prepare a tagged v0.1.0 release.

The full Detection Pack release gate has not yet been met.

## References

- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)
- [Sysmon pipeline](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)
- [Processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines.html)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)

Scope follows SOC_Projects_Implementation_Plan(1).docx, pages 2–3,
dated 25 October 2026.

The PowerShell-context hypothesis is implemented as selected Office applications
directly spawning PowerShell. The scheduled-task hypothesis is implemented as
creation commands referencing AppData or Temp directory substrings.