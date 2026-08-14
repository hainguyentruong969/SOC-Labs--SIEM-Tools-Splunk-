# Dataset Notes

## Source
Curated Splunk / Sysmon process-creation telemetry for RemCom execution behavior.

## Local ingestion
- Source: `remcom_windows-sysmon-fixed.txt`
- The fixed file was normalized so each XML event is separated and ingested as a distinct event.
- Splunk validation showed 11 separate events after normalization.

## Primary telemetry
- Sysmon Event ID 1 - Process Creation

## Host
- `mswin-server.attackrange.local`

## Key fields used
- `UtcTime`
- `Computer`
- `User`
- `ProcessId`
- `ProcessGuid`
- `ParentProcessId`
- `ParentImage`
- `ParentCommandLine`
- `Image`
- `CommandLine`

## Important limitation
This dataset validates known positive cases. It does not establish a false-positive rate for production environments.
