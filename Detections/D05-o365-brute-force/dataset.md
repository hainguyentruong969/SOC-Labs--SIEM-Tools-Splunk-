# Dataset Notes

## Source
`o365_brute_force_login.json`

## Authentication activity observed
The dataset includes Microsoft 365 audit operations such as:
- `UserLoginFailed`
- `UserLoggedIn`

The broader dataset also contains unrelated Microsoft 365 operations, so D07 intentionally filters to authentication activity for the detection and investigation.

## Important timestamp note
Splunk `_time` in this lab reflected local ingest timing rather than the original authentication timeline. The investigation therefore uses the event's `CreationTime` field and converts it into `EventTime` for correlation.

## Key fields
- `CreationTime` - original authentication event time
- `UserId` - account involved
- `ClientIP` - source IP of the authentication activity
- `Operation` - login failure or login success
- `ResultStatus` - failed or succeeded status
- `UserAgent` - client context when populated
- `Workload` - Microsoft 365 workload context when populated

## Scope limitation
This package validates the detection against curated attack telemetry. It does not establish a production false-positive rate or independently prove account compromise.
