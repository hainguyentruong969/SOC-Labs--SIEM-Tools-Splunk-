# Validation

## Positive test
The detection successfully identified `schtasks.exe /create` activity in known Atomic Red Team telemetry.

## Strongest event
- Host: `win-dc-893.attackrange.local`
- Task: `T1053_005_OnStartup`
- Trigger: `ONSTART`
- Run-as: `SYSTEM`
- Payload: `cmd.exe /c calc.exe`
- Technique: `T1053.005`

## Lifecycle validation
The task lifecycle was visible in the telemetry:

- `2020-12-07 12:36:14.478` - CREATE
- `2020-12-07 12:36:17.915` - DELETE

This supports the conclusion that the search logic is matching the intended scheduled-task test sequence.

## False-positive note
No broad benign baseline was evaluated in this package. Therefore, this project should claim positive validation against curated attack telemetry, not a measured production false-positive rate.

## Screenshot evidence
1. `01-eventid-overview.png`
2. `02-scheduled-task-detection.png`
3. `03-onstartup-system-alert.png`
4. `04-process-chain.png`
5. `05-create-delete-timeline.png`
