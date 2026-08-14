# D02 - LSASS Credential Dumping Detection

## Overview
Detect suspicious access to `lsass.exe` using Sysmon Event ID 10 and correlate with Sysmon Event ID 1.

## MITRE ATT&CK
- Tactic: Credential Access
- Technique: OS Credential Dumping
- Sub-technique: LSASS Memory
- Technique ID: T1003.001

## Data Source
- Sysmon Event ID 10 - Process Access
- Sysmon Event ID 1 - Process Creation
- Local sourcetype: `window-sysmon2`

## Detection Development

### Version 1
Search for Sysmon Event ID 10 where the target is `lsass.exe`.

Result:
```text
163 events
```

### Version 2
Filter LSASS access events using:
```text
0x1010
0x1410
```

Result:
```text
3 investigation candidates
```

Observed source processes:
```text
powershell.exe
rundll32.exe
taskmgr.exe
```

## Investigation
A high-interest event showed:

```text
SourceImage: C:\Windows\System32\rundll32.exe
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1410
SourceProcessId: 3352
Computer: win-dc-807.attackrange.local
```

Correlating PID 3352 with Sysmon Event ID 1 revealed:

```text
ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

Image:
C:\Windows\System32\rundll32.exe
```

Command line:

```text
"C:\Windows\System32\rundll32.exe" C:\windows\System32\comsvcs.dll MiniDump 868 C:\Users\ADMINI~1\AppData\Local\Temp\lsass-comsvcs.dmp full
```

## Investigation Chain
```text
PowerShell
    |
    v
rundll32.exe
    |
    v
comsvcs.dll MiniDump
    |
    v
lsass.exe PID 868
    |
    v
lsass-comsvcs.dmp
```

## Key Findings
- LSASS access alone is noisy.
- Event ID 10 is useful for identifying processes accessing LSASS.
- Filtering access rights reduced the investigation scope.
- Correlating Event ID 10 with Event ID 1 exposed the actual dump command.
- `rundll32.exe` with `comsvcs.dll MiniDump` was observed dumping LSASS memory.

## Detection Limitations
The rule does not assume every LSASS access is malicious. Legitimate processes such as `taskmgr.exe` may also appear.

The access masks are used as investigation indicators, not proof of credential dumping.

## Screenshots
![Event ID Distribution](screenshots/01-eventid-distribution.png)

![V1 LSASS Access](screenshots/02-v1-lsass-access.png)

![V2 Filtered LSASS Access](screenshots/03-v2-filtered-lsass-access.png)

![Rundll32 LSASS MiniDump](screenshots/04-rundll32-lsass-minidump.png)

## Result
The detection reduced 163 LSASS access events to 3 investigation candidates. Correlation with process-creation telemetry identified LSASS dumping via:

```text
PowerShell -> rundll32.exe -> comsvcs.dll MiniDump -> lsass.exe
```

Validated against curated attack telemetry.
