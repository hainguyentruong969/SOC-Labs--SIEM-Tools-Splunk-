# Investigation

## Detection seed
The account `bpatel@rodsoto.onmicrosoft.com` produced 75 `UserLoginFailed` events. The failures were associated with source IP `73.15.72.101`.

## Why the activity is suspicious
The failures occurred in dense bursts rather than as isolated user mistakes. The tuned detection found multiple 5-minute windows with at least 10 failures, including windows containing 17, 19, 23, and 12 failed login events.

## Trace methodology
Unlike endpoint process investigations, O365 authentication events are not traced with PID/PPID. The investigation correlates authentication artifacts:

- `UserId` - victim/account anchor
- `CreationTime` - chronological ordering
- `ClientIP` - source of authentication attempts
- `Operation` - failed or successful login activity
- `ResultStatus` - outcome of the operation

The analyst first pivots on the victim account, reconstructs the authentication timeline, and then pivots on the source IP to determine broader targeting.

## Success-after-failure correlation
After the failure burst beginning around `2020-12-15 18:52:11`, successful `UserLoggedIn` events were observed for the same account from the same source IP. Examples begin around `18:53:02`.

This correlation increases the severity of the finding because the sequence is consistent with:

`repeated failures -> successful authentication from same IP`

However, success events from that IP were also present elsewhere in the dataset. Therefore the evidence supports **possible account compromise**, not definitive compromise attribution.

## Source-IP pivot
The source IP `73.15.72.101` generated 97 failed login events across 5 distinct accounts. This shows that the credential activity was broader than a single-account attempt and warrants investigation for spraying or other multi-account credential attack behavior.

## Analyst conclusion
The telemetry is consistent with an O365 brute-force credential attack against `bpatel@rodsoto.onmicrosoft.com`, with repeated bursts of failed authentication from `73.15.72.101`. A successful authentication from the same IP shortly after the failure burst raises the possibility of account compromise. The source-IP pivot also shows broader targeting across multiple accounts.
