# Validation

## Positive validation results
The fixed dataset ingests as 11 separate Sysmon events and the broad RemCom detection returns 11 matching process-creation events.

## Strongest evidence
The strongest positive indicators are:

- `Image = remcom.exe`
- remote-style target in command line (`\\localhost` or `\\127.0.0.1`)
- credential switches (`/user:`, `/usr:`, `-u`)
- payload execution (`calc.exe`)
- parent processes of `cmd.exe` or `powershell.exe`

## Detection levels
- Broad detection (all `remcom.exe`): 11 events
- Tuned remote-execution detection (target + credential pattern): 10 events

## False-positive note
No benign baseline was tested in this package. Therefore, the correct claim is positive validation against curated attack telemetry, not a measured production-quality detection with known false-positive rate.

## Screenshot evidence
1. `01-dataset-validation.png`
2. `02-remcom-execution-detection.png`
3. `03-detection-v1.png`
4. `04-detection-v2-remote-execution.png`
5. `05-parent-process-investigation.png`
6. `06-remote-target-analysis.png`
