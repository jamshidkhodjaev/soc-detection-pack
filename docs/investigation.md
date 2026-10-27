# Investigation case study — IIS worker spawning a command shell

## Case status and scope

This is a synthetic investigation exercise based on the Detection Pack fixtures.
It is not a report of a real compromise.

The exercise demonstrates detection reasoning and an investigation plan.
No IIS server, endpoint, or live SIEM was investigated for this case.

Assessment: suspicious process relationship requiring investigation.
Compromise is not confirmed.

## Detection hypothesis

An IIS worker, w3wp.exe, directly creating cmd.exe, powershell.exe,
or pwsh.exe warrants investigation.

This relationship may be consistent with command execution through an
application or web shell. Approved application functionality can also
produce the same relationship.

Both parent and child executable predicates must match.

## Evidence available

Source: fixtures/iis_positive.jsonl
Record ID: syn-iis-001
Data provenance: fabricated JSONL event labeled synthetic=true.

| Field | Observed fixture value |
| --- | --- |
| timestamp_utc | 2026-10-25T12:00:00Z |
| host | IIS-LAB01 |
| EventID | 1 |
| ParentImage | C:\Windows\System32\inetsrv\w3wp.exe |
| Image | C:\Windows\System32\cmd.exe |
| CommandLine | cmd.exe /c whoami |
| User | IIS APPPOOL\PortfolioPool |

The source model is normalized Sysmon process creation.
The record is synthetic; its fields do not establish that an actual
process ran or that genuine Sysmon telemetry was collected.

## Observed facts and interpretation

| Observation | Interpretation and limit |
| --- | --- |
| ParentImage ends with \w3wp.exe | Satisfies the rule's IIS-parent predicate |
| Image ends with \cmd.exe | Satisfies the shell-child predicate |
| CommandLine contains /c whoami | Represents a request to run an identity query; no output or success is recorded |
| User names an application-pool identity | Provides execution context; does not establish authorization or privilege level |

The fixture supports a rule match. It does not identify an initiating
HTTP request, attacker, vulnerable application, web shell, or specific CVE.

## Competing explanations

### Possible unauthorized execution

An attacker may have induced an IIS-hosted application to launch a shell.
The represented identity query could be consistent with checking
the execution context.

This is a hypothesis, not an established finding.

### Possible legitimate application behavior

Approved diagnostics, application functionality, or administrative
automation may launch a command interpreter.

Application-owner confirmation, code review, and correlated logs would
be needed to assess this explanation.

## Investigation plan

The following steps describe additional work that would be required
in a real environment. They were not performed in this exercise.

1. Verify the original event source, provider/channel, timestamp, and field
   extraction. Confirm that the record represents Sysmon process creation.

2. Retrieve process identifiers, process GUIDs, parent identifiers,
   command lines, and related events to reconstruct process ancestry.

3. Identify the IIS application pool, hosted application, application owner,
   and relevant deployment or diagnostic activity.

4. Review IIS and application logs around the event time, accounting for
   timezone differences. Look for requests that can be correlated with
   the application and process activity. Time proximity alone is insufficient.

5. Inspect related endpoint activity, including additional child processes,
   file changes, persistence attempts, and outbound connections.

6. Review relevant application files and deployment history for unexpected
   changes. Do not infer the presence of a web shell from this process event alone.

7. Compare the behavior with approved functionality and historical activity.
   Document the evidence supporting either a legitimate or unauthorized explanation.

## Response considerations

No containment or remediation action was executed.

For a real incident, response would depend on corroborating evidence,
business impact, and the organization's response procedures.

A single rule match would not automatically justify blocking an address,
disabling an account, deleting a file, or isolating a production server.

## Detection validation

Rule: rules/iis_worker_spawning_shell.yml
Manifest: tests/iis_manifest.json

The local evaluator reads the actual Sigma YAML.

| Fixture ID | Scenario | Expected result |
| --- | --- | --- |
| syn-iis-001 | IIS spawning CMD | Match |
| syn-benign-001 | Explorer spawning CMD | No match |
| syn-iis-002 | IIS spawning PowerShell | Match |
| syn-benign-002 | IIS spawning Notepad | No match |
| syn-incomplete-001 | ParentImage missing | No match without a crash |

All five fixture expectations passed.

Mutation checks detected removal of either the parent or child predicate.
These checks demonstrate sensitivity to those specific rule changes,
not complete defect coverage.

Reproduce the local checks:

```bash
python scripts/parse_rule.py rules/iis_worker_spawning_shell.yml
python scripts/evaluate.py tests/iis_manifest.json
python scripts/mutation_check.py tests/iis_manifest.json
```

Generated query: converted/iis_worker_spawning_shell.spl

SPL generation completed, but the query has not been executed in Splunk.

## Blind spots and limitations

- Only the listed executable names and direct parent-child relationships are covered.
- Renamed executables, indirect execution, and in-process execution can fall outside coverage.
- Missing Image or ParentImage prevents this rule from matching.
- Approved IIS application behavior can produce a match.
- The fixtures do not establish real-world precision or recall.
- No command output, HTTP request logs, file evidence, or network evidence
  was collected for this exercise.
- The IIS pwsh.exe branch has no dedicated positive fixture.

## Final assessment

The synthetic record syn-iis-001 satisfies the IIS-to-shell detection hypothesis.

The defensible conclusion is that the represented behavior warrants investigation.
Unauthorized execution, successful exploitation, and compromise remain unconfirmed.

The next investigative requirement would be corroborating endpoint and
application evidence, together with validation of approved application behavior.