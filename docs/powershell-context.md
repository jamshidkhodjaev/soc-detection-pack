# Detection hypothesis — Office spawning PowerShell

## Hypothesis

Flag Windows process-creation events where Word, Excel, PowerPoint,
or Outlook directly creates powershell.exe or pwsh.exe.

This relationship may indicate script execution initiated through an
Office application. A match is an investigation lead, not proof of
a malicious document or compromise.

## Required detection fields

- ParentImage: full path of the direct parent executable.
- Image: full path of the child executable.

Use the existing normalized Sysmon Event ID 1 fixture contract.
CommandLine and User provide investigation context.

## Legitimate lookalikes

Approved Office macros, add-ins, or business automation may launch PowerShell.

## Boundaries

Only direct parent-child relationships and the listed executable names
are covered. Indirect execution, renamed executables, and other Office
applications are outside this initial rule.

The rule does not inspect script contents or establish obfuscation.

## Fixture coverage

All fixtures are synthetic normalized Sysmon Event ID 1 records.

| Fixture ID | Scenario | Expected match |
| --- | --- | --- |
| syn-office-001 | Word spawning Windows PowerShell | true |
| syn-office-002 | Excel spawning PowerShell 7 | true |
| syn-office-benign-001 | Explorer spawning Windows PowerShell | false |
| syn-office-benign-002 | Word spawning Notepad | false |
| syn-office-incomplete-001 | Word parent with Image missing | false |

The benign cases challenge the parent and child predicates separately.
Their non-match does not establish that the activity is safe.

The incomplete case omits Image. CommandLine still mentions PowerShell,
but the rule does not use CommandLine as a detection predicate.
Missing Image therefore produces a non-match without a crash.

The current fixtures cover Word and Excel as positive parents.
PowerPoint and Outlook are included in the rule but do not yet have
dedicated positive fixtures.

## Validation record

Local validation completed on 26 October 2026:

- pySigma parsing passed.
- All five fixture expectations passed.
- Removing ParentImage|endswith was detected by fixture failures.
- Removing Image|endswith was detected by fixture failures.
- Mutation checks operated on in-memory copies.
- SPL was generated using the Splunk backend and Sysmon pipeline.
- The generated SPL has not been executed in Splunk.

Reproduction commands:

```bash
python scripts/parse_rule.py rules/office_spawning_powershell.yml
python scripts/evaluate.py tests/office_manifest.json
python scripts/mutation_check.py tests/office_manifest.json
sigma convert -t splunk -p sysmon -f default -o converted/office_spawning_powershell.spl rules/office_spawning_powershell.yml
```

Five synthetic cases and two detected mutations do not establish
real-world accuracy or complete defect coverage.