# Validation status

Date: 26 October 2026

## IIS rule milestone

Rule: rules/iis_worker_spawning_shell.yml

- pySigma parsing passed.
- Five synthetic fixture expectations passed:
  - IIS spawning CMD: match.
  - Explorer spawning CMD: no match.
  - IIS spawning PowerShell: match.
  - IIS spawning Notepad: no match.
  - Missing ParentImage: no match, without a crash.
- Repeatable mutation checks detected removal of both essential predicates:
  - ParentImage|endswith
  - Image|endswith
- Mutations operate on in-memory copies; the original YAML is unchanged.
- SPL was generated using the Splunk backend and Sysmon pipeline.
- Dependency versions are recorded in requirements.lock.txt.

## Limitations

- All event fixtures are synthetic.
- The local evaluator supports only the documented restricted Sigma subset.
- Passing fixtures does not establish real-world detection accuracy.
- Generated SPL has not been executed in Splunk.
- A missing-field non-match does not establish that an event is safe.

## Remaining project work

- Implement and test the suspicious PowerShell-context rule.
- Implement and test the process-based scheduled-task-creation rule.
- Add GitHub Actions checks.
- Write the investigation summary.
- Complete clean-checkout reproduction.
- Prepare the full Detection Pack release.