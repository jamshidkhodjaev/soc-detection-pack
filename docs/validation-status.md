# Validation status

Date: 26 October 2026

## Current milestone

Two of the three planned Sigma rules are implemented with synthetic
fixture evaluation, predicate-removal mutation checks, and SPL conversion.

| Check | IIS spawning a shell | Office spawning PowerShell |
| --- | --- | --- |
| pySigma parsing | Passed | Passed |
| Positive fixtures | 2/2 passed | 2/2 passed |
| Benign boundary fixtures | 2/2 passed | 2/2 passed |
| Incomplete-event fixture | 1/1 passed | 1/1 passed |
| Predicate-removal mutations | 2/2 detected | 2/2 detected |
| SPL conversion using Sysmon pipeline | Completed | Completed |
| Execution in Splunk | Not tested | Not tested |

Totals: ten fixture expectations passed and four predicate-removal
mutations detected across two rules.

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

The fixture set detected removal of either ParentImage|endswith
or Image|endswith.

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

The fixture set detected removal of either ParentImage|endswith
or Image|endswith.

## Shared validation tooling

The evaluator reads the actual Sigma YAML selection.

The mutation script accepts a manifest path. Without an argument,
it defaults to tests/iis_manifest.json.

Each mutation run first requires the original rule to pass.
Mutations operate on separate in-memory copies and do not modify
the original YAML files.

Execution errors are not counted as detected mutations.

Dependency versions are recorded in requirements.lock.txt.

## Reproduction commands

Run from the repository root with the virtual environment active.

### Parsing

```bash
python scripts/parse_rule.py rules/iis_worker_spawning_shell.yml
python scripts/parse_rule.py rules/office_spawning_powershell.yml