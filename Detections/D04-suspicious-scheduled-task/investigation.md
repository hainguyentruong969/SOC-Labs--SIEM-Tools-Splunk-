# Investigation

## Initial detection
A broad search for `schtasks.exe` process creation with `/create` returned multiple Scheduled Task creations.

The most suspicious test case was:

`SCHTASKS /Create /TN "T1053_005_OnStartup" /SC ONSTART /RU SYSTEM /TR "cmd.exe /c calc.exe"`

Indicators supporting escalation of the alert:

- Uses `schtasks.exe`
- Creates a task instead of merely querying one
- Trigger is system startup (`ONSTART`)
- Task runs as `SYSTEM`
- Task launches a command shell payload
- Activity appears inside an Atomic Red Team test chain

## Host
`win-dc-893.attackrange.local`

## User
`ATTACKRANGE\Administrator`

## Process trace
The event chain was reconstructed using Sysmon Event ID 1 and parent/child relationships.

Observed sequence:

1. `winrshost.exe`
2. `cmd.exe`
3. `powershell.exe`
4. `powershell.exe`
5. `powershell.exe`
6. `cmd.exe`
7. `schtasks.exe`

The exact evidence should be correlated with:
- `UtcTime`
- `ProcessId`
- `ParentProcessId`
- `Image`
- `ParentImage`
- `CommandLine`

## Why ProcessId alone is not enough
PIDs can be reused over time. During a real investigation, correlate PID relationships inside a narrow time window and prefer process GUIDs when available.

## Analyst conclusion
The telemetry is consistent with a Scheduled Task persistence test mapped to T1053.005. Because the dataset is Atomic Red Team telemetry, the correct statement is that the detection was successfully validated against known simulated attack behavior, not that a real attacker compromised the host.
