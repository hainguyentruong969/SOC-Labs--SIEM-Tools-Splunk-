# Attack Story - O365 Brute Force

A source IP, `73.15.72.101`, generated repeated failed Microsoft 365 authentication attempts against several accounts. The account `bpatel@rodsoto.onmicrosoft.com` was the primary target, with 75 failed login events.

The failures occurred in concentrated bursts, including multiple 5-minute windows containing more than 10 failed authentication events. This pattern is consistent with brute-force behavior rather than occasional user password mistakes.

After the failure burst began, successful authentication events were observed for the same account from the same source IP. This sequence raises the possibility that the credential attack resulted in a valid login, although additional context would be required to definitively confirm account compromise.

A pivot on the source IP showed 97 failed login events targeting 5 distinct accounts, indicating broader credential-attack activity beyond the primary victim.

## Simplified flow

`73.15.72.101 -> repeated failures -> bpatel account -> success from same IP -> possible account compromise`

The same source IP also targeted multiple other Microsoft 365 accounts, which should be investigated separately for password-spraying characteristics.
