# Detection hypothesis — Scheduled-task creation referencing AppData or Temp

## Hypothesis

Flag normalized Windows process-creation events where:

- `Image` ends with `\schtasks.exe`.
- `CommandLine` contains both `/create` and `/tr`.
- `CommandLine` contains `\AppData\`, `\Temp\`, `%APPDATA%`, or `%TEMP%`.

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
A referenced path or variable is not necessarily the `/tr` target; it may occur
in a task name or another argument. The evaluator does not bind it to `/tr`.
Switch-like text embedded in other arguments may also match.

The literal directory forms retain both backslash boundaries. `\Temp\` is not
broadened to `\Temp`: `C:\Tempest\demo.exe`, `C:\Templates\demo.exe`, and bare
`C:\Temp` do not satisfy it. `C:\AppDatabase\demo.exe` similarly does not satisfy
`\AppData\`. The percent signs delimit complete variable names, so
`%TEMP_BACKUP%` and `%APPDATA_BACKUP%` do not satisfy the added literals.
These boundaries do not turn substring matching into path or argument parsing.

It does not expand environment variables or resolve paths.
It does not determine directory permissions.

Task creation through APIs, PowerShell cmdlets, or renamed executables
is outside this rule.

Process creation shows a command being launched, not its outcome.
Confirm task registration and inspect the task definition during investigation.

## Literal environment variables and switch evidence

The added tokens match literal characters in the observed `CommandLine`.
Environment variables may already be expanded before process-creation telemetry
is recorded, depending on the launcher and invocation. For example, Microsoft's
[cmd documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)
describes substitution of percent-delimited environment variables. The evaluator
does not simulate that substitution. These synthetic fixtures validate
literal-string matching, not how often that form occurs in real telemetry,
whether schtasks accepts the supplied task action, or successful task creation.
The chosen synthetic parent is context, not evidence of a captured cmd launch.

Microsoft's [schtasks create syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
documents `/create` and `/tr`. Support for `-create`/`-tr` is an **unverified
extension**, left out of this rule. No Windows execution was performed to establish
acceptance or rejection. The hyphen-only negative fixture tests the rule's scope,
not Windows command validity.

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
| syn-task-003 | Literal %APPDATA% reference; validates observed string matching only. | true |
| syn-task-004 | Literal %TEMP% reference in lowercase exercises case-insensitive matching. | true |
| syn-task-boundary-001 | Literal AppData reference cannot bypass the /create requirement. | false |
| syn-task-boundary-002 | Literal Temp reference cannot bypass the /tr requirement. | false |
| syn-task-boundary-003 | Matching command text cannot bypass the schtasks.exe Image requirement. | false |
| syn-task-boundary-004 | Tempest is not a Temp path component. | false |
| syn-task-boundary-005 | Templates is not a Temp path component. | false |
| syn-task-boundary-006 | AppDatabase is not an AppData path component. | false |
| syn-task-boundary-007 | A bare directory lacks the trailing path separator required by the literal path predicate. | false |
| syn-task-boundary-008 | A different variable name must not match the complete %APPDATA% token. | false |
| syn-task-boundary-009 | A different variable name must not match the complete %TEMP% token. | false |
| syn-task-boundary-010 | Hyphen-switch extension is unverified and intentionally unsupported; this is not Windows syntax validation. | false |

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

See the authoritative [validation record](validation-status.md) for counts,
mutation results, parsing, SPL comparisons, and historical CI evidence.

## Reproduction commands

Run from the repository root with the virtual environment active.

```bash
python scripts/parse_rule.py rules/schtasks_creation_suspicious_path.yml
python scripts/evaluate.py tests/schtasks_manifest.json
python scripts/mutation_check.py tests/schtasks_manifest.json
python scripts/convert_rule.py -o converted/schtasks_creation_suspicious_path.spl rules/schtasks_creation_suspicious_path.yml
```

CI runs regression tests, fixture evaluation, predicate/value mutation checks,
parsing, and SPL regeneration/diffs. This maintenance update is unpublished.

## Limitations

Synthetic cases and detected mutations do not establish
real-world accuracy or complete defect coverage.

A process-creation event records the command being launched.
Successful task registration requires additional evidence, such as
task-registration events or the resulting task definition.

## ATT&CK context

[T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
covers abuse of Windows Task Scheduler for execution, persistence, or privilege
escalation. The tags describe investigative context, not a conclusion that these
techniques occurred. A process match does not confirm registration or execution
of a task. This focused pass adds literal variable references only; executable,
slash-switch, and directory-boundary requirements are preserved.
