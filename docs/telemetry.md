# Telemetry contract — IIS worker spawning a shell

## Hypothesis

If a Windows process-creation event records `w3wp.exe` as the direct parent of
`cmd.exe`, `powershell.exe`, or `pwsh.exe`, flag it for investigation.

An attacker executing commands through a compromised IIS application or web
shell may produce this relationship. Legitimate applications can also launch
shells; a match is not proof of compromise or a particular CVE.

Both parent and child predicates must match. `CommandLine` and `User` provide
investigation context; they are not detection predicates.

## Source and normalization

One Sigma logsource:

```yaml
logsource:
    category: process_creation
    product: windows
```

The intended collection model is Sysmon Event ID 1: process creation.

All current fixtures are synthetic. Live Windows collection is outside the
current implementation.

Each fixture contains one UTF-8 JSON object on one physical line.
JSON escapes backslashes: `C:\\Windows` becomes `C:\Windows` after parsing.

Parsing performs no case conversion, basename extraction, or slash rewriting.
Case-insensitive comparison occurs during matching.

`Image` and `ParentImage` represent full Windows executable paths, not command
lines. The evaluator checks string suffixes; it does not validate that these
strings are well-formed Windows paths.

| Field | Type | Requirement and meaning |
| --- | --- | --- |
| `synthetic` | boolean | Required `true`; explicitly labels fabricated data |
| `event_id` | string | Required fixture identifier matching the manifest; distinct from the Windows event number |
| `timestamp_utc` | string | Required parseable ISO 8601 timestamp ending in `Z` |
| `host` | string | Required nonempty source computer name |
| `product` | string | Required routing field; `windows` is in scope |
| `category` | string | Required routing field; `process_creation` is in scope |
| `EventID` | integer | Required routing field; integer `1` is in scope |
| `Image` | string | Child executable path; referenced detection field |
| `ParentImage` | string | Direct parent executable path; referenced detection field |
| `CommandLine` | string | Required nonempty context; not a detection predicate |
| `User` | string | Required nonempty child-process security principal; not a detection predicate |

Complete fixtures supply both detection fields. Incomplete fixtures may
deliberately omit a referenced detection field to test missing-field behavior.

The current incomplete fixture omits `ParentImage` while retaining routing
metadata and required context.

For a future real-event normalizer:

- Map Sysmon `UtcTime` to `timestamp_utc`.
- Map the source computer identity to `host`.
- Preserve the meanings of `Image`, `ParentImage`, `CommandLine`, and `User`.
- Derive `event_id` from a stable record identifier.
- Establish the Sysmon provider/channel before treating Event ID 1 as
  process creation.

Event numbers alone are not globally unique. The current synthetic fixtures
are scoped to Sysmon by this contract; the evaluator does not independently
verify a provider/channel field.

## Local evaluator contract

The evaluator loads the actual Sigma YAML rather than hard-coding
individual detection rules.

Supported detection structure:

- One nonempty mapping named `selection`.
- `condition: selection`.
- AND between all selection entries.
- Case-insensitive comparison using Python `casefold`.

Supported field modifiers:

| Syntax | Meaning |
| --- | --- |
| `FIELD|endswith` | Match at least one literal suffix |
| `FIELD|contains` | Match at least one literal substring |
| `FIELD|contains|all` | Match every listed literal substring |

Each entry accepts a nonempty literal string or a nonempty list of
nonempty literal strings.

For `endswith` and plain `contains`, list values use OR.
For `contains|all`, list values use AND.

Different entries can reference the same event field with different
supported modifiers. Each entry remains a separate required predicate.

The current fixtures use ASCII Windows paths. A literal backslash before
an executable name provides a path-component boundary for suffix matching.

Wildcards (`*` and `?`), regular expressions, other modifiers, other condition
expressions, correlation, filters, and custom taxonomy are unsupported.
Unsupported syntax causes an error.

Backslashes are matched literally after JSON or YAML decoding.
The evaluator does not interpret Sigma wildcard escape syntax.

Matching does not parse command-line arguments, expand environment
variables, resolve paths, or establish whether a command succeeded.

The IIS and Office rules use `endswith`.
The scheduled-task rule additionally uses `contains` and `contains|all`.

### Missing fields and invalid inputs

- Missing or null referenced detection fields evaluate false.
- Present detection fields with non-string values cause an error.
- Missing routing metadata causes an error.
- `EventID` must be an integer.
- Different product, category, or integer event type values are out of scope
  and evaluate false.
- Invalid JSON, empty fixtures, or fixtures with multiple physical records
  cause an error.
- Required context must remain present, including in the current incomplete case.
- The evaluator's command-line YAML loader rejects duplicate mapping keys.

The manifest stores expected outcomes separately from events. Expected results
are used to assess matching results; they are not detection inputs.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | All fixture expectations passed |
| `1` | At least one fixture expectation failed |
| `2` | Invalid input, unsupported syntax, or another execution error |

Run:

```bash
python scripts/evaluate.py tests/iis_manifest.json
```

## Current fixture coverage

| Fixture ID | File | Scenario | Expected match |
| --- | --- | --- | --- |
| `syn-iis-001` | `fixtures/iis_positive.jsonl` | IIS worker spawning CMD | `true` |
| `syn-benign-001` | `fixtures/iis_benign.jsonl` | Explorer spawning CMD | `false` |
| `syn-iis-003` | `fixtures/iis_positive_pwsh.jsonl` | IIS worker spawning PowerShell 7 | `true` |
| `syn-iis-002` | `fixtures/iis_positive_powershell.jsonl` | IIS worker spawning PowerShell | `true` |
| `syn-benign-002` | `fixtures/iis_benign_non_shell.jsonl` | IIS worker spawning Notepad | `false` |
| `syn-incomplete-001` | `fixtures/iis_incomplete_missing_parent.jsonl` | CMD event missing `ParentImage` | `false` |

See the [validation record](validation-status.md) for counts and evidence.

The Explorer case challenges the parent predicate. It uses the same shell and
command as the first positive case.

The Notepad case challenges the child predicate. It is outside this rule's
shell list, even though its parent is IIS. This synthetic boundary case does
not establish that IIS spawning Notepad is legitimate in a real environment.

The incomplete case confirms that a missing `ParentImage` produces a non-match
without a crash. A non-match caused by missing telemetry does not establish
that an event is safe.

The dedicated `syn-iis-003` fixture covers IIS directly spawning `pwsh.exe`.

## Mutation-check contract

Run:

```bash
python scripts/mutation_check.py
```

The script first requires the original rule to pass all fixture expectations.
It then enumerates the selected rule's selection entries, creates a separate
in-memory copy for each entry, and removes that entry from its copy.

| Mutation | Expected test response |
| --- | --- |
| Remove `ParentImage|endswith` | The Explorer-to-CMD benign expectation fails |
| Remove `Image|endswith` | The IIS-to-Notepad benign expectation fails |

Other affected fixtures may also fail.

A mutation is detected when fixture evaluation returns an expectation failure.
Execution errors do not count as detected mutations.

Results are recorded in the [validation record](validation-status.md).
The original YAML file is not modified.

These checks demonstrate that the fixture set catches two specific ways of
weakening the rule. Individual values in multi-value selection lists are also
removed one at a time; only expectation mismatches count as detected mutations.
They do not establish complete coverage of possible defects.

## Splunk conversion contract

Use the Splunk backend and predefined `sysmon` pipeline:

```bash
python scripts/convert_rule.py -o converted/iis_worker_spawning_shell.spl rules/iis_worker_spawning_shell.yml
```

Sysmon field names `Image` and `ParentImage` are retained. The pipeline adds
`EventID=1` for process creation.

The generated query uses raw Sysmon fields rather than Splunk CIM/tstats.
The rule's `fields` section supplies displayed columns through a `table` clause;
it does not add matching conditions.

The normalization-only fields `event_id`, `synthetic`, `product`, and `category`
are not assumed to be native Sysmon fields and are not detection predicates.

No index name is assumed. A real deployment must establish the correct data
scope, provider/channel, field extraction, and access controls, then test
the query against ingested events.

Conversion is separate from fixture evaluation. The local evaluator does not
execute SPL, and the generated query has not been run in Splunk.

## Detection boundaries and triage

Approved IIS application behavior can satisfy the rule. Investigate such
matches before considering a narrowly scoped exception.

Coverage limitations include:

- Renamed executables.
- Indirect descendants rather than direct child processes.
- In-process execution without a matching child process.
- Shell names outside the rule's list.
- Missing parent or child telemetry.

Before concluding that exploitation occurred, review:

- Process ancestry and related process events.
- Full command lines and execution timing.
- The account and application-pool context.
- IIS request logs and relevant application activity.
- Approved application functionality and administrative activity.

The synthetic fixture outcomes do not establish precision, recall, or
operational detection effectiveness.

## Milestone boundary

This is an experimental, synthetic-only detection pack. The v0.1.0 pre-release
exists; this v0.1.1 maintenance update is unpublished. See the authoritative
[validation record](validation-status.md) for current counts, independently
verified historical CI, recorded clean-checkout claims, and release steps.

## ATT&CK context

[T1505.003 — Web Shell](https://attack.mitre.org/techniques/T1505/003/) describes
server-side web shells that can provide command execution. IIS spawning a shell
is a contextual investigation lead for that technique, not proof that a web shell
exists or the technique occurred. The rule intentionally has no rule-wide
PowerShell-specific tag because its child list also covers `cmd.exe`.
