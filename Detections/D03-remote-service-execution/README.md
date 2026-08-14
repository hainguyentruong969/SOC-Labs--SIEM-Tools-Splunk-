# D03 - Remote Service Execution (RemCom)

## Objective
Detect and investigate Windows remote service execution behavior associated with RemCom from Sysmon process-creation telemetry.

## MITRE ATT&CK
- Technique: T1569.002 - System Services: Service Execution
- Primary tactic: Execution
- Possible secondary context: Lateral Movement, depending on remote target and environment

## Dataset
- Local Splunk source: `remcom_windows-sysmon-fixed.txt`
- Primary telemetry: Sysmon Event ID 1 (Process Creation)
- Main investigated host: `mswin-server.attackrange.local`
- Tool observed: `remcom.exe`

## Detection Summary
The dataset contains repeated executions of `remcom.exe` from an Atomic Red Team path:

`C:\AtomicRedTeam\atomics\T1569.002\bin\remcom.exe`

Evidence shows command lines targeting `\\localhost` and `\\127.0.0.1`, with credential switches such as `/user:`, `/usr:`, and `-u`, and payloads including `calc.exe` or `C:\Windows\System32\calc.exe`.

## Investigation Summary
The available Sysmon Event ID 1 telemetry supports these conclusions:

- 11 separate process-creation events for `remcom.exe`
- 10 events explicitly show a remote-style target (`\\localhost` or `\\127.0.0.1`)
- Parent processes include both `cmd.exe` and `powershell.exe`
- Multiple command-line variations were tested, which is consistent with adversary-emulation or validation activity

## Validation
This package validates positive detection logic against known attack-simulation telemetry. It should not be presented as proof of a real intrusion.

## Files
- `detection-v1.spl` - broad RemCom detection
- `detection-v2.spl` - tuned remote-execution detection
- `parent-process-investigation.spl` - parent/child process tracing
- `remote-target-analysis.spl` - extraction of remote target and credential style
- `dataset.md` - data notes
- `investigation.md` - analyst investigation notes
- `validation.md` - validation notes
- `screenshots/` - Splunk evidence
