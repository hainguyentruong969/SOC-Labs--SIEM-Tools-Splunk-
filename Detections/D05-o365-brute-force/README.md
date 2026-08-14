# D07 - O365 Brute Force Detection and Investigation

## Objective
Detect and investigate a Microsoft 365 credential attack by identifying bursts of failed logins against the same account, reconstructing the authentication timeline, checking for subsequent successful logins, and pivoting on the source IP to determine broader targeting.

## MITRE ATT&CK
- Technique: T1110 - Brute Force
- Tactic: Credential Access

## Dataset
- Source: `o365_brute_force_login.json`
- Primary event types: `UserLoginFailed`, `UserLoggedIn`
- Primary investigation fields: `CreationTime`, `UserId`, `ClientIP`, `Operation`, `ResultStatus`

## Main Finding
The strongest victim account in the dataset is:

`bpatel@rodsoto.onmicrosoft.com`

Observed evidence:
- 75 failed login events for the account
- Primary source IP: `73.15.72.101`
- Multiple failure bursts exceeded 10 failures within 5-minute windows
- Successful `UserLoggedIn` events were observed from the same source IP shortly after the failure burst
- The same source IP generated 97 failed logins against 5 accounts

The success-after-failure correlation increases the suspicion of account compromise, but this package uses the conservative conclusion **possible account compromise** because additional contextual telemetry would be required for definitive attribution.

## Detection Logic
### V1 - Account-based threshold
Identify accounts with at least 10 failed login events.

### V2 - Time-window threshold
Identify accounts with at least 10 failed login events within a 5-minute window, while preserving source IP context.

## Investigation Method
1. Start from the victim account identified by the detection.
2. Reconstruct the authentication timeline using `CreationTime`.
3. Correlate failed and successful logins by `UserId` and `ClientIP`.
4. Check whether successful authentication occurred after the failure burst from the same source IP.
5. Pivot on the source IP and determine how many accounts it targeted.

## Key Question Answers
### How was it detected?
Repeated `UserLoginFailed` events were aggregated by account, then tuned with a 5-minute time window and threshold.

### How was it traced?
The alert was pivoted through `UserId` -> `CreationTime` -> `ClientIP` -> `Operation` / `ResultStatus`, followed by a source-IP pivot across other accounts.

### What evidence supports the trace?
`CreationTime`, `UserId`, `ClientIP`, `Operation`, and `ResultStatus` form the core authentication-correlation chain.

## Files
- `detection-v1.spl`
- `detection-v2.spl`
- `victim-timeline.spl`
- `post-failure-success.spl`
- `source-ip-pivot.spl`
- `dataset.md`
- `investigation.md`
- `validation.md`
- `screenshots/`
