# SOC Detection Pack

Experimental SOC detection engineering portfolio project by Jamshid Khodjaev.

This project develops Sigma rules with documented telemetry assumptions,
synthetic behavioral tests, mutation checks, and conversion to Splunk SPL.

The current IIS rule has passed pySigma parsing, five synthetic fixture
expectations, two predicate-removal mutation checks, and SPL conversion using
the Sysmon pipeline. The full three-rule Detection Pack remains in progress.

All fixtures are synthetic. The generated SPL has not been executed in Splunk.
No production readiness or measured detection accuracy is claimed.

## Current validation status

Local validation on macOS, 26 October 2026:

| Check | Result |
| --- | --- |
| Sigma rules implemented | 1 of 3 planned |
| pySigma parsing | Passed for the IIS shell rule |
| Local behavioral evaluation | 5/5 fixture expectations passed |
| Predicate-removal mutation checks | 2/2 mutations detected |
| Splunk conversion | SPL generated using the `sysmon` pipeline |
| Dependency versions | Recorded in `requirements.lock.txt` |
| SPL execution in Splunk | Not tested |
| GitHub Actions | Not implemented |
| Clean-checkout reproduction | Pending |
| Full Detection Pack | In progress |

See [the validation record](docs/validation-status.md) for results and remaining work.

## Detection hypothesis

If a Windows process-creation event records `w3wp.exe` as the direct parent of
`cmd.exe`, `powershell.exe`, or `pwsh.exe`, flag it for investigation.

This relationship may indicate command execution through a compromised IIS
application or web shell. Approved application functionality can also invoke a
shell, so a match is an investigation lead rather than proof of compromise.

Both the parent and child predicates must match. `CommandLine` and `User`
provide investigation context; they are not detection predicates.

The rule covers direct parent-child relationships only.

## Planned detection scope

| Behavior | Status |
| --- | --- |
| IIS worker directly spawning a Windows shell | Implemented with initial validation |
| PowerShell execution with suspicious context | Planned; exact hypothesis to be defined |
| Process-based scheduled-task creation | Planned; exact hypothesis to be defined |

The scheduled-task rule will address a documented command-line behavior,
rather than every method of creating a scheduled task.

## Repository contents

| Path | Purpose |
| --- | --- |
| `rules/iis_worker_spawning_shell.yml` | Experimental IIS-to-shell Sigma rule |
| `fixtures/iis_positive.jsonl` | IIS worker spawning CMD |
| `fixtures/iis_positive_powershell.jsonl` | IIS worker spawning PowerShell |
| `fixtures/iis_benign.jsonl` | Explorer spawning CMD |
| `fixtures/iis_benign_non_shell.jsonl` | IIS worker spawning a non-shell executable |
| `fixtures/iis_incomplete_missing_parent.jsonl` | Shell event without `ParentImage` |
| `tests/iis_manifest.json` | Fixtures, expected outcomes, and reasons |
| `scripts/parse_rule.py` | Separate pySigma parsing check |
| `scripts/evaluate.py` | Restricted local Sigma evaluator |
| `scripts/mutation_check.py` | Repeatable IIS predicate-removal checks |
| `converted/iis_worker_spawning_shell.spl` | Generated Splunk query |
| `docs/telemetry.md` | Telemetry contract and matching semantics |
| `docs/validation-status.md` | Validation record and remaining work |
| `requirements.in` | Direct dependencies |
| `requirements.lock.txt` | Resolved dependency versions used locally |

## Setup

Open the project folder in VS Code or navigate to it in macOS Terminal.
Run the following commands from the repository root.

The observed local validation used Python 3.13.0.

Check Python:

```bash
python3 --version
```

For a fresh setup, create a virtual environment:

```bash
python3 -m venv .venv
```

Skip creation if a working `.venv` already exists.

Activate it:

```bash
source .venv/bin/activate
```

Activation applies to the current terminal session. If that session already
has the correct environment active, no additional activation is needed.

Install the recorded dependencies:

```bash
python -m pip install -r requirements.lock.txt
```

The direct dependencies listed in `requirements.in` are:

```text
sigma-cli
pysigma-backend-splunk
PyYAML
pysigma-pipeline-sysmon
```

Sigma CLI uses pySigma for parsing. The Splunk backend generates SPL, the
Sysmon pipeline supplies event mapping, and PyYAML loads YAML for local checks.

`requirements.lock.txt` records the resolved versions used for local validation.
Installation and reproduction from a clean checkout remain to be verified.

Virtual environments and backup environments should not be committed to Git.

## Input contract and fixture cases

The source model is Windows Sysmon Event ID 1: process creation.

Fixtures use normalized JSON Lines. Each current fixture contains one JSON
object on one physical line and is explicitly labeled `"synthetic": true`.

- `event_id` identifies a synthetic fixture record.
- `EventID` is the numeric Windows event type.
- `Image` identifies the child executable.
- `ParentImage` identifies its direct parent.
- `CommandLine` and `User` provide context.
- `product` and `category` provide local event-routing metadata.

Expected results are stored in the manifest, separately from event inputs.

| Fixture ID | Scenario | Expected match |
| --- | --- | --- |
| `syn-iis-001` | IIS worker spawning CMD | `true` |
| `syn-benign-001` | Explorer spawning CMD | `false` |
| `syn-iis-002` | IIS worker spawning PowerShell | `true` |
| `syn-benign-002` | IIS worker spawning Notepad | `false` |
| `syn-incomplete-001` | CMD event missing `ParentImage` | `false` |

The Notepad case is a synthetic test of the rule's child-process boundary.
It does not establish that IIS spawning Notepad is legitimate in a real system.

A missing-parent non-match means the required relationship cannot be established.
It does not establish that the event is safe.

JSON escapes backslashes: `C:\\Windows` represents `C:\Windows` after parsing.
Single-quoted YAML strings preserve literal backslashes.

See [the telemetry contract](docs/telemetry.md) for matching and source assumptions.

## Check A: parse the Sigma rule

```bash
python scripts/parse_rule.py rules/iis_worker_spawning_shell.yml
```

Expected:

```text
PASS: pySigma parsed 1 rule (no fixture evaluation or SPL execution)
```

This checks that pySigma understands the rule structure and detection syntax.
It does not evaluate fixtures or establish complete validation against the
official Sigma JSON Schema.

## Check B: evaluate synthetic fixtures

```bash
python scripts/evaluate.py tests/iis_manifest.json
```

Expected:

```text
PASS syn-iis-001: expected=True actual=True
PASS syn-benign-001: expected=False actual=False
PASS syn-iis-002: expected=True actual=True
PASS syn-benign-002: expected=False actual=False
PASS syn-incomplete-001: expected=False actual=False
5/5 fixture expectations passed
```

The evaluator reads the actual YAML selection and applies its predicates to
the fixtures. It does not hard-code the IIS detection or execute generated SPL.

Supported subset:

- One nonempty mapping named `selection`.
- `condition: selection`.
- `FIELD|endswith` with a nonempty literal string or list of such strings.
- AND between fields and OR between list values.
- Case-insensitive matching using Python `casefold`.
- Missing or null referenced detection fields evaluate false.
- Unsupported detection syntax and invalid inputs cause an error.

Routing metadata is checked separately. Missing routing fields cause an error;
events with a different product, category, or event type do not match.

This is a restricted project evaluator, not a general Sigma engine.
Later rules may require explicit extensions to its supported syntax.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | All fixture expectations passed |
| `1` | At least one fixture expectation failed |
| `2` | Invalid input, unsupported syntax, or another execution error |

## Check C: test whether fixtures catch weakened rules

```bash
python scripts/mutation_check.py
```

Expected:

```text
PASS: original rule passes all fixture expectations
PASS: tests caught removal of ParentImage|endswith
PASS: tests caught removal of Image|endswith
2/2 mutations detected; original YAML file unchanged
```

The script first verifies that the original rule passes. It then makes separate
in-memory copies and removes one essential predicate from each copy.

| Mutation | Boundary case that exposes the mistake |
| --- | --- |
| Remove `ParentImage|endswith` | Explorer spawning CMD incorrectly matches |
| Remove `Image|endswith` | IIS spawning Notepad incorrectly matches |

The mutation check passes when fixture evaluation detects each deliberate
mistake. An execution error is not counted as a detected mutation.

The script does not write changes to the original YAML file.

These checks demonstrate sensitivity to two specific predicate-removal mistakes.
They do not establish that the fixtures detect every possible rule defect.

## Check D: convert to Splunk SPL

```bash
sigma convert -t splunk -p sysmon -f default -o converted/iis_worker_spawning_shell.spl rules/iis_worker_spawning_shell.yml
```

Expected: conversion completes without an error and writes a nonempty query.

Display the result:

```bash
cat converted/iis_worker_spawning_shell.spl
```

The locally generated query is:

```spl
EventID=1 ParentImage="*\\w3wp.exe" Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe") | table Image,ParentImage,CommandLine,User
```

Formatting and condition order may vary with backend versions.

- `-t splunk` selects the backend.
- `-p sysmon` selects the mapping pipeline.
- `-f default` selects the output format.
- `-o` selects the output file.

The pipeline supplies `EventID=1` for process creation while retaining raw
Sysmon field names. This query uses raw fields rather than Splunk CIM/tstats.

The `table` clause controls displayed columns; it adds no matching conditions.

No Splunk index is assumed. A future deployment must confirm the data scope,
Sysmon provider/channel, field extraction, and actual query behavior.
Event numbers alone do not uniquely identify an event provider.

## What the checks demonstrate

| Check | Demonstrates | Does not demonstrate |
| --- | --- | --- |
| Parsing | pySigma understands the rule | Correct matching behavior |
| Fixture evaluation | Five expected synthetic outcomes | Real-world accuracy or SPL correctness |
| Mutation checks | Fixtures catch two predicate-removal mistakes | Complete defect coverage |
| Conversion | SPL generation with the selected pipeline | Successful execution in Splunk |

Parsing, behavioral evaluation, mutation checking, and conversion are separate
checks. The fixture and mutation commands are project scripts.

## Limitations

- All event fixtures are synthetic; live Windows collection is not part of
  the current implementation.
- Approved IIS application behavior can match this rule.
- Renamed executables, indirect descendants, in-process execution, other shell
  names, and absent parent telemetry can fall outside coverage.
- `pwsh.exe` is included in the rule but has no dedicated positive fixture yet.
- Five fixtures cannot establish precision, recall, or operational effectiveness.
- The restricted evaluator does not execute or validate the behavior of SPL.
- The generated query has not been run in Splunk.
- CI and clean-checkout reproduction remain pending.

Investigation should review process ancestry, full command lines, accounts,
IIS request logs, and approved application behavior before concluding that
exploitation occurred.

## Remaining work

- Define, implement, and test the suspicious PowerShell-context rule.
- Define, implement, and test the process-based scheduled-task-creation rule.
- Extend the evaluator explicitly if additional rule syntax is needed.
- Reach at least two positive, two benign, and one incomplete case per rule.
- Parse and convert all three rules.
- Add GitHub Actions checks that expose failures.
- Write an evidence-based investigation summary.
- Complete reproduction from a clean checkout.
- Review documentation consistency and prepare a tagged `v0.1.0` release.

The IIS fixture and mutation milestone is complete. The full Detection Pack
acceptance criteria have not yet been met.

## References

- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)
- [Sysmon pipeline](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)
- [Processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines.html)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)

Scope follows `SOC_Projects_Implementation_Plan(1).docx`, pages 2–3,
dated 25 October 2026.