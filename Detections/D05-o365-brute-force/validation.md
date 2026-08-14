# Validation

## Positive detection evidence
- Total `UserLoginFailed` events in dataset: 132
- Strongest victim: `bpatel@rodsoto.onmicrosoft.com`
- Failures for victim: 75
- Main source IP: `73.15.72.101`

## Tuned detection evidence
The 5-minute detection produced multiple windows exceeding the threshold of 10 failures for the same account and source IP.

Observed examples:
- `2020-12-15 18:50:00` - 17 failures
- `2020-12-15 18:55:00` - 19 failures
- `2020-12-15 19:25:00` - 23 failures
- `2020-12-16 23:05:00` - 12 failures

## Post-failure authentication
Successful `UserLoggedIn` events were observed from `73.15.72.101` for the same account after the failure burst. This supports escalation to **possible account compromise**.

## Broader source-IP activity
`73.15.72.101` generated:
- 97 failed login events
- 5 targeted accounts

## False-positive note
The threshold of 10 failures in 5 minutes is used for lab validation and should be tuned against normal authentication behavior in a production environment.

## Screenshot evidence
1. `01-operation-overview.png`
2. `02-failures-by-user-and-ip.png`
3. `03-detection-v1.png`
4. `04-detection-v2-5m-window.png`
5. `05-victim-failure-timeline.png`
6. `06-post-failure-success.png`
7. `07-source-ip-pivot.png`
