# D04 - Suspicious Scheduled Task

## Objective
Detect and investigate suspicious Windows Scheduled Task creation from Sysmon process-creation telemetry.

## MITRE ATT&CK
- Technique: T1053.005 - Scheduled Task/Job: Scheduled Task
- Primary tactic: Persistence
- Possible secondary tactic: Privilege Escalation, depending on task context

## Dataset
- Splunk Attack Data / Atomic Red Team telemetry
- Local Splunk sourcetype: `window-sysmon3`
- Main investigated host: `win-dc-893.attackrange.local`
- Primary telemetry: Sysmon Event ID 1 (Process Creation)

## Detection Summary
The dataset contains multiple `schtasks.exe /create` executions. The strongest test case is:

- Task name: `T1053_005_OnStartup`
- Trigger: `/sc onstart`
- Run context: `/ru system`
- Action: `/tr "cmd.exe /c calc.exe"`
- User observed in telemetry: `ATTACKRANGE\Administrator`

This is known attack-simulation telemetry and should not be described as evidence of a real-world compromise.

## Investigation Summary
The process chain around the suspicious task creation can be reconstructed from Sysmon parent/child process relationships:

`winrshost.exe -> cmd.exe -> powershell.exe -> powershell.exe -> powershell.exe -> cmd.exe -> schtasks.exe`

The chain is supported by `ProcessId`, `ParentProcessId`, image paths, command lines, host, and event timestamps.

## Validation
The same task was later deleted:

- CREATE: `2020-12-07 12:36:14.478`
- DELETE: `2020-12-07 12:36:17.915`

This confirms the full Atomic Red Team test lifecycle in the available telemetry.

## Files
- `detection-v1.spl` - broad Scheduled Task creation detection
- `detection-v2.spl` - tuned detection for startup tasks running as SYSTEM
- `investigation.spl` - process-chain reconstruction query
- `timeline.spl` - task create/delete lifecycle
- `dataset.md` - data notes
- `investigation.md` - analyst investigation notes
- `validation.md` - validation evidence
- `screenshots/` - Splunk evidence
