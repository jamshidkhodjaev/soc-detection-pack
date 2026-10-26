# SOC Detection Pack

Experimental SOC detection engineering portfolio project by Jamshid Khodjaev.

This project develops Sigma rules with documented hypotheses, synthetic
event fixtures, behavioral evaluation, mutation checks, and Splunk SPL conversion.

Two of three planned rules are implemented. Across these rules, ten synthetic
fixture expectations passed and four predicate-removal mutations were detected.

All fixtures are synthetic. Generated SPL has not been executed in Splunk.
No production readiness or measured detection accuracy is claimed.

## Detection scope and status

| Rule | Hypothesis | Status |
| --- | --- | --- |
| IIS spawning a shell | An IIS worker directly creates CMD or PowerShell | Implemented with initial validation |
| Office spawning PowerShell | Word, Excel, PowerPoint, or Outlook directly creates PowerShell | Implemented with initial validation |
| Process-based scheduled-task creation | Exact suspicious command-line behavior to be defined | Planned |

Matches are investigation leads, not proof of compromise.
Approved application functionality or business automation may also match.

The IIS rule includes cmd.exe, powershell.exe, and pwsh.exe.
The Office rule includes powershell.exe and pwsh.exe.

## Current validation status

Local validation on macOS, 26 October 2026:

| Check | IIS rule | Office rule |
| --- | --- | --- |
| pySigma parsing | Passed | Passed |
| Synthetic fixture expectations | 5/5 passed | 5/5 passed |
| Predicate-removal mutations | 2/2 detected | 2/2 detected |
| SPL conversion with Sysmon pipeline | Completed | Completed |
| Execution in Splunk | Not tested | Not tested |

Project-wide checks still pending:

- GitHub Actions.
- Investigation write-up.
- Clean-checkout reproduction.
- Full three-rule release.

See [the validation record](docs/validation-status.md) for details.

## Repository structure

| Path | Purpose |
| --- | --- |
| `rules/` | Experimental Sigma YAML rules |
| `fixtures/` | Synthetic normalized JSONL events |
| `tests/iis_manifest.json` | IIS fixtures, expected outcomes, and reasons |
| `tests/office_manifest.json` | Office fixtures, expected outcomes, and reasons |
| `scripts/parse_rule.py` | pySigma parsing check |
| `scripts/evaluate.py` | Restricted local Sigma evaluator |
| `scripts/mutation_check.py` | Parent- and child-predicate removal checks |
| `converted/` | Generated Splunk SPL queries |
| `docs/telemetry.md` | IIS hypothesis and telemetry/evaluator contract |
| `docs/powershell-context.md` | Office hypothesis, boundaries, and validation |
| `docs/validation-status.md` | Validation results and remaining work |
| `requirements.in` | Direct dependencies |
| `requirements.lock.txt` | Resolved dependency versions used locally |

## Setup

Run commands from the repository root in macOS Terminal or VS Code's terminal.

The observed local validation used Python 3.13.0.

Check Python:

```bash
python3 --version
```

For a fresh setup, create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Skip environment creation if a working `.venv` already exists.
Activation applies separately to each terminal session.

Install the recorded dependencies:

```bash
python -m pip install -r requirements.lock.txt
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

Installation and reproduction from a clean checkout remain unverified.
Virtual environments and backup environments should not be committed to Git.

## Input contract

The intended source model is Windows Sysmon Event ID 1: process creation.

Each current fixture contains one UTF-8 JSON object on one physical line
and carries `"synthetic": true`.

| Field | Meaning |
| --- | --- |
| `event_id` | Synthetic record identifier, distinct from the Windows event number |
| `EventID` | Numeric Windows event type; integer 1 is in scope |
| `timestamp_utc` | Event timestamp ending in Z |
| `host` | Source computer |
| `product`, `category` | Local routing metadata |
| `Image` | Child executable path |
| `ParentImage` | Direct parent executable path |
| `CommandLine`, `User` | Investigation context |

Both current rules require matching Image and ParentImage values.
CommandLine and User are not detection predicates.

Expected outcomes live in manifests, separately from event inputs.
Incomplete fixtures deliberately omit a detection field.

JSON escapes backslashes: `C:\\Windows` represents `C:\Windows` after parsing.

A real normalizer must establish the Sysmon provider/channel.
An event number alone does not identify its provider.

## Fixture coverage

### IIS rule

| Fixture ID | Scenario | Expected match |
| --- | --- | --- |
| syn-iis-001 | IIS spawning CMD | true |
| syn-benign-001 | Explorer spawning CMD | false |
| syn-iis-002 | IIS spawning PowerShell | true |
| syn-benign-002 | IIS spawning Notepad | false |
| syn-incomplete-001 | CMD event missing ParentImage | false |

### Office rule

| Fixture ID | Scenario | Expected match |
| --- | --- | --- |
| syn-office-001 | Word spawning Windows PowerShell | true |
| syn-office-002 | Excel spawning PowerShell 7 | true |
| syn-office-benign-001 | Explorer spawning Windows PowerShell | false |
| syn-office-benign-002 | Word spawning Notepad | false |
| syn-office-incomplete-001 | Word parent with Image missing | false |

Benign boundary cases test events outside a rule's conditions.
A non-match does not establish that the activity is safe.

Likewise, a missing-field non-match means the available data cannot satisfy
the rule. The current incomplete fixtures return false without crashing.

## Check A: parse the rules

```bash
python scripts/parse_rule.py rules/iis_worker_spawning_shell.yml
python scripts/parse_rule.py rules/office_spawning_powershell.yml
```

Each command should report:

```text
PASS: pySigma parsed 1 rule (no fixture evaluation or SPL execution)
```

Parsing checks that pySigma understands the rule structure and detection syntax.
It does not establish matching correctness or complete official JSON Schema validation.

## Check B: evaluate fixtures

```bash
python scripts/evaluate.py tests/iis_manifest.json
python scripts/evaluate.py tests/office_manifest.json
```

Each command should end with:

```text
5/5 fixture expectations passed
```

The evaluator reads the actual YAML selection rather than hard-coding
the intended detection.

Supported subset:

- One nonempty mapping named `selection`.
- `condition: selection`.
- `FIELD|endswith` with nonempty literal strings or lists of such strings.
- AND between fields and OR between list values.
- Case-insensitive comparison using Python `casefold`.
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
```

Each command should report:

```text
PASS: original rule passes all fixture expectations
PASS: tests caught removal of ParentImage|endswith
PASS: tests caught removal of Image|endswith
2/2 mutations detected; original YAML file unchanged
```

Without a manifest argument, the script defaults to tests/iis_manifest.json.

The script first requires the original rule to pass. It then removes one
predicate from each of two separate in-memory copies.

| Removed predicate | Boundary case that catches the mistake |
| --- | --- |
| ParentImage, IIS rule | Explorer spawning CMD |
| Image, IIS rule | IIS spawning Notepad |
| ParentImage, Office rule | Explorer spawning PowerShell |
| Image, Office rule | Word spawning Notepad |

Execution errors do not count as detected mutations.
The script does not modify the original YAML files.

Mutation checks demonstrate sensitivity to these specific mistakes;
they do not establish complete defect coverage.

## Check D: generate Splunk SPL

```bash
sigma convert -t splunk -p sysmon -f default -o converted/iis_worker_spawning_shell.spl rules/iis_worker_spawning_shell.yml
sigma convert -t splunk -p sysmon -f default -o converted/office_spawning_powershell.spl rules/office_spawning_powershell.yml
```

Each command should complete without errors and produce a nonempty query.

Inspect the generated files:

```bash
cat converted/iis_worker_spawning_shell.spl
cat converted/office_spawning_powershell.spl
```

The Sysmon pipeline adds EventID=1 and retains raw Image and ParentImage fields.
These queries use raw Sysmon fields rather than Splunk CIM/tstats.

The table clause selects displayed investigation fields; it adds no predicates.

No Splunk index is assumed. A real deployment must establish the correct data
scope, provider/channel, and field extraction, then execute and test the query.

## What validation demonstrates

| Check | Demonstrates | Does not demonstrate |
| --- | --- | --- |
| Parsing | pySigma understands each rule | Correct matching behavior |
| Fixture evaluation | Ten expected synthetic outcomes | Real-world accuracy or SPL correctness |
| Mutation checks | Four specific predicate removals are caught | Complete defect coverage |
| Conversion | SPL generation with the selected pipeline | Successful execution in Splunk |

Parsing, behavioral evaluation, mutation checking, and conversion are separate checks.
The evaluator does not execute generated SPL.

## Limitations and investigation guidance

- All current events are synthetic; live collection is outside this implementation.
- Approved applications, macros, add-ins, or automation may match.
- Renamed executables, indirect descendants, in-process execution, and executable
  names outside the lists can fall outside coverage.
- Missing telemetry can prevent matching.
- The IIS pwsh.exe branch has no dedicated positive fixture.
- Office PowerPoint and Outlook branches have no dedicated positive fixtures.
- The fixtures do not establish precision, recall, or operational effectiveness.
- Neither generated query has been executed in Splunk.
- Automated CI and clean-checkout reproduction remain pending.

Investigate process ancestry, command lines, accounts, timing, related logs,
and approved business behavior before concluding that compromise occurred.

## Remaining work

- Define and implement the process-based scheduled-task-creation rule.
- Add at least two positive, two benign, and one incomplete case for rule three.
- Extend the evaluator explicitly if additional syntax is required.
- Parse and convert the third rule.
- Add GitHub Actions checks that expose failures.
- Write an evidence-based investigation summary.
- Verify reproduction from a clean checkout.
- Review documentation and prepare a tagged v0.1.0 release.

The full Detection Pack release gate has not yet been met.

## References

- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)
- [Sysmon pipeline](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)
- [Processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines.html)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)

Scope follows SOC_Projects_Implementation_Plan(1).docx, pages 2–3,
dated 25 October 2026. The PowerShell-context hypothesis is implemented
as selected Office applications directly spawning PowerShell.