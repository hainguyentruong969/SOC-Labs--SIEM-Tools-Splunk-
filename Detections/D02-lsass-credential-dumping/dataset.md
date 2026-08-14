# Dataset

## Source
Splunk Attack Data telemetry for:

```text
T1003.001 - LSASS Memory
```

## Splunk Configuration
```text
Sourcetype: window-sysmon2
Time range: All time
```

## Event Distribution
Approximate imported events:
```text
7,974 Sysmon events
```

Important Event IDs:
```text
Event ID 1  - Process Creation
Event ID 10 - Process Access
```

## Validation Example
```text
Computer: win-dc-807.attackrange.local
SourceProcessId: 3352
SourceImage: C:\Windows\System32\rundll32.exe
TargetProcessId: 868
TargetImage: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1410
```
