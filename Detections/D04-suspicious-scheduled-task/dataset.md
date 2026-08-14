# Dataset Notes

## Source
Curated Splunk Attack Data / Atomic Red Team telemetry for Windows Scheduled Task behavior.

## Local ingestion
- Sourcetype: `window-sysmon3`
- XML fields are extracted at search time with `rex`.
- The original endpoint identity should be taken from the XML `Computer` field, not only Splunk metadata.

## Event IDs observed
The dataset contains Sysmon Event IDs including 1, 3, 4, 5, 6, 10, 11, 12, 13, and 22.

For this detection, the primary source is:

- Sysmon Event ID 1 - Process Creation

## Key fields
- `UtcTime`
- `Computer`
- `User`
- `ProcessId`
- `ParentProcessId`
- `Image`
- `ParentImage`
- `CommandLine`

## Important limitation
This dataset is known attack-simulation telemetry. It validates positive detection logic, but by itself does not prove low false-positive rates in normal enterprise environments.
