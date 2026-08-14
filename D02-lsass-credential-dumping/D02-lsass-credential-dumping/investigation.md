# Investigation - LSASS Credential Dumping

## Alert Context
```text
UtcTime: 2020-11-03 15:53:03.159
Computer: win-dc-807.attackrange.local
SourceProcessId: 3352
SourceImage: C:\Windows\System32\rundll32.exe
TargetProcessId: 868
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1410
```

## Correlation
Sysmon Event ID 1 for PID 3352:

```text
UtcTime: 2020-11-03 15:53:03.090
User: ATTACKRANGE\Administrator
ProcessId: 3352
ParentProcessId: 3184
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Image: C:\Windows\System32\rundll32.exe
```

Command line:

```text
"C:\Windows\System32\rundll32.exe" C:\windows\System32\comsvcs.dll MiniDump 868 C:\Users\ADMINI~1\AppData\Local\Temp\lsass-comsvcs.dmp full
```

## Timeline
```text
15:53:03.090 - PowerShell launches rundll32.exe
15:53:03.159 - rundll32.exe accesses lsass.exe
```

Difference: approximately 69 ms.

## Conclusion
The process-access event alone was not enough. Correlation with process-creation telemetry revealed explicit LSASS memory dumping using `rundll32.exe` and `comsvcs.dll MiniDump`.

MITRE ATT&CK: T1003.001 - LSASS Memory
