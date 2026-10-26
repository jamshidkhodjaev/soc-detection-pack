# Telemetry contract — IIS worker spawning a shell

## Hypothesis
If a Windows process-creation event records w3wp.exe as the direct parent
of cmd.exe, powershell.exe, or pwsh.exe, flag it for investigation.
An attacker executing commands through a compromised IIS application or web shell
may produce this relationship. Legitimate applications can also launch shells;
a match is not proof of compromise or a particular CVE.

## Source and normalization
One logsource: product=windows, category=process_creation.
The intended collection model is Sysmon Event ID 1 (process creation).
For this milestone, all records are fabricated; no Windows collection is running.
One UTF-8 JSON object per physical line. Each JSONL file contains one record.
Backslashes in JSON strings are escaped: C:\\Windows becomes C:\Windows after parsing.
No case conversion, basename extraction or slash rewriting happens during parsing.
Image and ParentImage represent full Windows paths, not command lines.

| Field | Type | Requirement and meaning |
| --- | --- | --- |
| synthetic | boolean | Required true; explicit fabricated-data label |
| event_id | string | Required unique fixture record ID; NOT the Windows event number |
| timestamp_utc | string | Required UTC timestamp ending Z; ISO 8601 |
| host | string | Required source computer name |
| product | string | Required windows; local logsource routing metadata |
| category | string | Required process_creation; local logsource routing metadata |
| EventID | integer | Required 1; numeric Sysmon process-creation event type |
| Image | string | Detection field: newly created child executable path |
| ParentImage | string | Detection field: direct parent executable path |
| CommandLine | string | Required context for complete fixtures; not a predicate |
| User | string | Required context for complete fixtures; child process security principal |

For a later real normalizer: Sysmon UtcTime -> timestamp_utc,
Computer -> host, Image/ParentImage/CommandLine/User retain their meanings.
Generate event_id from a stable record identifier. Provider/channel must establish
that EventID 1 is Sysmon, since event numbers alone are not globally unique.
These fixtures are explicitly scoped to Sysmon by this contract.

## Local evaluator contract
The evaluator loads the actual rule YAML, rather than hard-coding IIS predicates.
Allowed detection: one nonempty mapping named selection and condition: selection.
Allowed field syntax: FIELD|endswith with a nonempty string or list of strings.
Mapping entries use AND. Values in a list use OR. String comparison is
case-insensitive (Python casefold; these fixtures use ASCII paths).
No wildcards (* or ?), regex, escapes, other modifiers, other condition syntax,
correlation, filters or custom taxonomy are supported; unsupported input errors out.
The literal backslash preceding a filename is a path-component boundary.
Missing/null referenced fields evaluate false. Non-string present fields error out.
Missing routing metadata errors out; wrong product/category or EventID is out of
scope and evaluates false. No missing-field test is claimed for this milestone.
Invalid JSON and empty fixtures fail. The manifest stores expectations separately
from the event, so expected outcomes cannot influence the detection.

## Splunk conversion contract
Use the Splunk backend and the predefined sysmon pipeline. Sysmon field names
Image and ParentImage are retained; the pipeline scopes process creation to
EventID=1. This is raw Sysmon SPL, not Splunk CIM/tstats.
The normalization-only fields event_id, synthetic, product and category are not
assumed to be native Sysmon fields and are not rule predicates.
No index name is invented. A real deployment must supply the correct data scope,
provider/channel, field extraction and access controls and execute the SPL.
Conversion is not fixture evaluation; the local evaluator does not execute SPL.

## Boundaries and triage
Positive: w3wp.exe -> cmd.exe /c whoami under an application-pool identity.
Benign boundary: explorer.exe -> the exact same child and command.
This challenges the parent predicate. Removing it should make that benign case fail.
An approved IIS application invoking cmd.exe still matches: document and investigate
that false positive before considering a narrowly scoped exception.
Renamed executables, indirect descendants, in-process execution, absent parent
telemetry and other shell names are outside this initial rule's coverage.
Review process ancestry, full command line, account, IIS request logs and approved
application behavior before concluding that exploitation occurred.

## Milestone boundary
Only one rule, one positive fixture and one benign fixture are delivered here.
The full project still needs additional variants, incomplete records, mutation
coverage, CI, an investigation write-up and two further rules. Do not claim the
complete Detection Pack release gate has been met.
