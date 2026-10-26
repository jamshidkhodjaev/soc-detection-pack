# SOC Detection Pack

Experimental SOC detection engineering portfolio project by Jamshid Khodjaev.

The first milestone is complete: one Sigma rule detecting an IIS worker directly
spawning a Windows shell has passed pySigma parsing, two synthetic fixture checks,
and conversion to Splunk SPL using the Sysmon pipeline. The full Detection Pack
remains in progress. All event fixtures are synthetic. The generated SPL has not
been executed in Splunk, and no production readiness or measured accuracy is claimed.

## Current validation status

Results observed locally on macOS on 26 October 2026:

| Check | Result |
| --- | --- |
| pySigma parsing | Passed for the IIS shell rule |
| Local behavioral evaluation | 2/2 fixture expectations passed |
| Splunk conversion | SPL generated using the `sysmon` pipeline |
| Dependency versions | Recorded in `requirements.lock.txt` |
| SPL execution in Splunk | Not tested |
| Full Detection Pack | In progress |

See `docs/validation-status.md` for the validation record and remaining work.

## Detection hypothesis

If a Windows process-creation event records `w3wp.exe` as the direct parent of
`cmd.exe`, `powershell.exe`, or `pwsh.exe`, flag it for investigation.

This relationship may indicate command execution through a compromised IIS
application or web shell. Approved application functionality can also invoke a
shell, so a match is an investigation lead rather than proof of compromise.
Both the parent and child predicates must match. `CommandLine` and `User` provide
investigation context; they are not detection predicates.

## Repository contents

| Path | Purpose |
| --- | --- |
| `rules/iis_worker_spawning_shell.yml` | Experimental Sigma rule |
| `fixtures/iis_positive.jsonl` | Synthetic IIS worker spawning a shell |
| `fixtures/iis_benign.jsonl` | Explorer spawning the same shell and command |
| `tests/iis_manifest.json` | Rule, fixtures, expected outcomes, and reasons |
| `scripts/parse_rule.py` | Separate pySigma parsing check |
| `scripts/evaluate.py` | Restricted local Sigma evaluator |
| `converted/iis_worker_spawning_shell.spl` | Generated Splunk query |
| `docs/telemetry.md` | Telemetry contract and matching semantics |
| `docs/validation-status.md` | Validation record and limitations |
| `requirements.in` | Direct dependencies |
| `requirements.lock.txt` | Installed versions used for validation |

## 1. Open the project and activate Python

In macOS Terminal, type `cd `, drag your `soc-detection-pack` folder into the
window, and press Return. Expected: no output; Terminal is now in the project root.

Check Python:

```bash
python3 --version
```

Expected: a Python version. The observed local checks used Python 3.13.

For a fresh setup, create a virtual environment. Skip creation if you already
have a working `.venv`:

```bash
python3 -m venv .venv
```

Expected: no output and a new `.venv` folder.

Activate it in each new Terminal session:

```bash
source .venv/bin/activate
```

Expected: the prompt usually starts with `(.venv)`. Packages remain separate from
the rest of the Mac. Do not upload `.venv` or backup environments to GitHub.

## 2. Install the recorded dependencies

With the virtual environment activated:

```bash
python -m pip install -r requirements.lock.txt
```

Expected: the recorded package versions install successfully, or pip reports
that they are already installed. Stop if installation fails.

The direct dependencies listed in `requirements.in` are:

```text
sigma-cli
pysigma-backend-splunk
PyYAML
pysigma-pipeline-sysmon
```

Sigma CLI uses pySigma for parsing. The Splunk backend generates SPL, the separate
Sysmon pipeline supplies event mapping, and PyYAML loads the rule for the evaluator.

Verify discovery and versions:

```bash
sigma list targets
sigma list pipelines
sigma version
```

Expected: targets includes `splunk`, pipelines includes `sysmon`, and the version
command displays Sigma version information.

`requirements.in` lists direct dependencies; `requirements.lock.txt` records the
resolved installed versions. A clean-checkout reproduction is still pending.

## 3. Read the input contract and examples

Open `docs/telemetry.md`, the rule, both fixtures, and `tests/iis_manifest.json`
in your editor.

Each JSONL fixture contains one JSON object on one physical line and carries
`synthetic: true`. The source model is Windows Sysmon Event ID 1, process creation.
`event_id` is a fixture identifier; `EventID` is the numeric Windows event type.

The positive example has an IIS worker parent. The benign example uses the same
`cmd.exe /c whoami` command but has `explorer.exe` as its parent, challenging the
parent predicate. Expected outcomes live in the manifest, outside detection inputs.

JSON escapes backslashes: `C:\\Windows` represents `C:\Windows` after parsing.
Single-quoted YAML strings preserve literal backslashes.

## 4. Check A: rule parsing

```bash
python scripts/parse_rule.py rules/iis_worker_spawning_shell.yml
```

Expected:

```text
PASS: pySigma parsed 1 rule (no fixture evaluation or SPL execution)
```

This checks that pySigma understands the rule structure and detection syntax.
It does not evaluate fixtures or establish complete validation against the
official Sigma JSON Schema. Stop and investigate any parsing error.

## 5. Check B: local behavioral evaluation

```bash
python scripts/evaluate.py tests/iis_manifest.json
```

Expected:

```text
PASS syn-iis-001: expected=True actual=True
PASS syn-benign-001: expected=False actual=False
2/2 fixture expectations passed
```

The evaluator reads the actual YAML selection and applies its predicates to the
fixtures. It does not hard-code the IIS detection or execute generated SPL.

Supported subset:

- One nonempty mapping named `selection` and `condition: selection`.
- `FIELD|endswith` with a literal string or nonempty list of literal strings.
- AND between fields and OR between list values.
- Case-insensitive comparison using Python `casefold`.
- Missing or null referenced fields evaluate false.
- Unsupported detection syntax and invalid inputs cause an error.

This is a restricted project evaluator, not a general Sigma engine. See
`docs/telemetry.md` for the complete contract, including event-source routing.

Exit `0`: expectations passed. Exit `1`: an expectation failed. Exit `2`: invalid
input or unsupported syntax.

## 6. Check C: convert to Splunk SPL

```bash
sigma convert -t splunk -p sysmon -f default -o converted/iis_worker_spawning_shell.spl rules/iis_worker_spawning_shell.yml
```

Expected: conversion completes without an error, possibly showing progress,
and writes a nonempty query file.

Display the result:

```bash
cat converted/iis_worker_spawning_shell.spl
```

Expected: a query equivalent to the following. Formatting and condition order
may vary by backend version.

```spl
EventID=1 ParentImage="*\\w3wp.exe" Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe") | table Image,ParentImage,CommandLine,User
```

`-t splunk` selects the backend, `-p sysmon` selects the pipeline, `-f default`
selects the output format, and `-o` sets the output file.

The pipeline supplies `EventID=1` for process creation while retaining raw Sysmon
field names. This uses raw fields rather than Splunk CIM/tstats. The `table`
clause comes from the rule's `fields` section and controls displayed columns;
it adds no matching conditions. No Splunk index is assumed. A future deployment
must confirm provider/data scope, field extraction, and actual query behavior.

## What the checks demonstrate

| Check | Demonstrates | Does not demonstrate |
| --- | --- | --- |
| Parsing | pySigma understands the rule | Correct matching behavior |
| Fixture evaluation | Two expected synthetic outcomes | Real-world accuracy or SPL correctness |
| Conversion | SPL generation with the selected pipeline | Successful execution in Splunk |

Sigma CLI does not provide the JSONL fixture-test command used here. Parsing,
behavioral evaluation, and conversion remain separate checks.

## Limitations and remaining work

Approved IIS application behavior may match. Renamed executables, indirect
descendants, in-process execution, other shell names, and absent parent telemetry
can fall outside coverage. Two examples cannot establish precision or recall.
No live collection, SIEM deployment, or operational effectiveness is claimed.

Remaining work:

- Add another positive variant and benign boundary case for the IIS rule.
- Add an incomplete-event fixture with a documented expected result.
- Add reproducible mutation testing that fails when an essential predicate is removed.
- Add rules for suspicious PowerShell context and process-based scheduled task
  creation, explicitly extending the evaluator if their syntax requires it.
- Add CI, a clean-checkout reproduction, and an investigation write-up.

The first-rule milestone is complete. The repository is experimental work in
progress; the full Detection Pack acceptance criteria have not yet been met.

## References

- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)
- [Sysmon pipeline](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)
- [Processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines.html)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)

Scope follows `SOC_Projects_Implementation_Plan(1).docx`, pages 2–3, dated
25 October 2026.
