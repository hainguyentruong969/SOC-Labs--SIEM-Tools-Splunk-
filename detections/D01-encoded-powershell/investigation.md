# Investigation Notes - D01 Encoded PowerShell

## Alert Type

Encoded PowerShell Execution

## Observed Event

- **UtcTime:** `2021-01-19 13:27:04.921`
- **Computer:** `win-dc-397.attackrange.local`
- **User:** `ATTACKRANGE\Administrator`
- **Process ID:** `5948`
- **Parent Process ID:** `4936`
- **Parent Process:** `C:\Windows\System32\cmd.exe`
- **Process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

## Command Line

```text
powershell.exe -Exec bypass -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACAAVwBvAHIAbABkACIA
```

## Payload Decoding

The Base64 value was decoded as UTF-16LE.

Decoded command:

```powershell
Write-Host "Hello World"
```

## Child Process Check

A search was performed for Sysmon Event ID 1 events where:

```text
ParentProcessId = 5948
```

Result:

```text
No events
```

No child process was created by this PowerShell process.

## Analysis

The use of `-enc` and `-Exec bypass` is suspicious because these options are commonly used to obscure PowerShell execution and reduce policy restrictions.

However, the decoded command only writes `Hello World` to the console.

The lack of child-process activity is consistent with the benign decoded payload.

## Verdict

**Suspicious technique / benign payload**

The event demonstrates a behavior that should be detected and investigated, but this specific execution does not provide evidence of malicious post-exploitation behavior.

## Detection Tuning Notes

The initial detection searched for the keyword `powershell.exe` and generated noise from:

```text
C:\Program Files\SplunkUniversalForwarder\bin\splunk-powershell.exe
```

The final version reduced this noise by:

1. Requiring the image path to end in `\powershell.exe`.
2. Requiring an encoded-command argument.
3. Extracting the encoded payload for investigation.
