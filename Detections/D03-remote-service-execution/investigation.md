# Investigation

## Initial detection
A broad search for process creations where `Image` ends with `remcom.exe` returned 11 events.

The executable path observed in the dataset is:

`C:\AtomicRedTeam\atomics\T1569.002\bin\remcom.exe`

## Why this is suspicious
Indicators supporting investigation escalation:

- The tool name is `remcom.exe`, which is associated with remote command execution.
- The command line references remote-style destinations such as `\\localhost` and `\\127.0.0.1`.
- Credential switches are present: `/user:`, `/usr:`, or `-u`.
- The payload being executed is `calc.exe`.
- The behavior comes from a T1569.002 Atomic Red Team test path.

## Remote execution patterns observed
Observed command-line patterns include:

- `\\localhost -u Administrator -p P@ssw0rd1 "C:\Windows\System32\calc.exe"`
- `\\localhost /user:Administrator /pwd:P@ssw0rd1 "C:\Windows\System32\calc.exe"`
- `\\localhost /usr:Administrator /pwd:P@ssw0rd1 "C:\Windows\System32\calc.exe"`
- `\\127.0.0.1 /user:Administrator /pwd:P@ssw0rd1 C:\Windows\System32\calc.exe`
- `\\127.0.0.1 /user:Administrator /pwd:P@ssw0rd1 calc.exe`

## Parent process context
Parent process tracing shows `remcom.exe` being launched from at least:

- `C:\Windows\System32\cmd.exe`
- `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

This strengthens the assessment that the dataset captures a scripted or operator-driven service execution test.

## Analyst conclusion
The telemetry is consistent with a validated Atomic Red Team exercise for MITRE ATT&CK T1569.002 (Service Execution). The search logic successfully detects RemCom execution and highlights remote target, credential style, and parent process context.
