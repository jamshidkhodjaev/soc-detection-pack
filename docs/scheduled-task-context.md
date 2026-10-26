# Detection hypothesis — Scheduled-task creation referencing AppData or Temp

## Hypothesis

Flag normalized Windows process-creation events where:

- `Image` ends with `\schtasks.exe`.
- `CommandLine` contains both `/create` and `/tr`.
- `CommandLine` contains `\AppData\` or `\Temp\`.

Matching is case-insensitive.

This may identify task-creation attempts referencing locations that warrant
investigation. A match does not establish malicious persistence or successful
task creation.

## Required detection fields

- Image: executable path.
- CommandLine: full process command line.

Use the existing normalized Sysmon Event ID 1 source model.
ParentImage and User provide investigation context.

## Legitimate lookalikes

Authorized installers, updaters, or administrative automation may create
tasks referencing AppData or Temp directories.

## Boundaries

This rule evaluates substrings, not parsed command-line arguments.
The directory reference may occur outside the actual task action.
Switch-like text embedded in other arguments may also match.

It does not expand environment variables or resolve paths.
It does not determine directory permissions.

Task creation through APIs, PowerShell cmdlets, or renamed executables
is outside this rule.

Process creation shows a command being launched, not its outcome.
Confirm task registration and inspect the task definition during investigation.

## Fixture coverage

All fixtures are synthetic normalized Sysmon Event ID 1 records.

| Fixture ID | Scenario | Expected match |
| --- | --- | --- |
| syn-task-001 | Creation command referencing AppData | true |
| syn-task-002 | Creation command referencing Temp, with uppercase executable and switches | true |
| syn-task-benign-001 | Creation command without AppData or Temp | false |
| syn-task-benign-002 | Task-change command missing /create | false |
| syn-task-benign-003 | XML-based creation command missing /tr | false |
| syn-task-benign-004 | Matching command text in a cmd.exe event | false |
| syn-task-incomplete-001 | Image missing | false |

Negative cases challenge the executable, required switches, and directory
conditions separately. A non-match does not establish that activity is safe.

The XML-based creation case documents a coverage limit: task creation without
an explicit /tr substring does not match this rule.

The incomplete fixture omits Image while retaining CommandLine and required
context. It returns false without a crash.

## Evaluator semantics

This rule uses the project's restricted evaluator with:

- Image|endswith: literal suffix matching.
- CommandLine|contains|all: every listed substring must appear.
- CommandLine|contains: at least one listed substring must appear.

All selection entries are joined by AND.
Comparisons are case-insensitive using Python casefold.

Matching uses substrings rather than parsed command-line arguments.
The evaluator does not expand environment variables, resolve paths,
inspect directory permissions, or establish command success.

## Validation record

Local validation completed on 26 October 2026:

- pySigma parsing passed.
- All seven fixture expectations passed.
- Three predicate-removal mutations were detected:
  - Image|endswith
  - CommandLine|contains|all
  - CommandLine|contains
- Mutations used in-memory copies; the original YAML was unchanged.
- SPL was generated using the Splunk backend and Sysmon pipeline.
- Generated SPL has not been executed in Splunk.

After the shared evaluator and mutation script were updated, both the IIS
and Office rules still passed their five fixture expectations and detected
their two predicate-removal mutations.

## Reproduction commands

Run from the repository root with the virtual environment active.

```bash
python scripts/parse_rule.py rules/schtasks_creation_suspicious_path.yml
python scripts/evaluate.py tests/schtasks_manifest.json
python scripts/mutation_check.py tests/schtasks_manifest.json
sigma convert -t splunk -p sysmon -f default -o converted/schtasks_creation_suspicious_path.spl rules/schtasks_creation_suspicious_path.yml
```

Expected fixture summary: 7/7 fixture expectations passed.

Expected mutation summary: 3/3 mutations detected.

## Automation status

A GitHub Actions workflow has been authored at:

.github/workflows/checks.yml

It is configured to install recorded dependencies, parse all three rules,
evaluate their fixtures, run mutation checks, and regenerate and compare SPL.

A successful GitHub Actions run has not yet been verified.

## Limitations

Seven synthetic cases and three detected mutations do not establish
real-world accuracy or complete defect coverage.

A process-creation event records the command being launched.
Successful task registration requires additional evidence, such as
task-registration events or the resulting task definition.