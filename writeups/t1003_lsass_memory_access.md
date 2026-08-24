# T1003.001 — LSASS Memory Credential Dumping

## Technique

An attacker can attempt to access the memory of the Windows Local Security Authority Subsystem Service (LSASS) process to obtain credentials handled by LSASS. This detection identifies suspicious processes requesting high levels of access to `lsass.exe`, which can indicate credential-dumping activity.

## Detection Logic

The Sigma rule detects Sysmon Event ID 10 (Process Access) events where:

* `TargetImage` ends in `\lsass.exe`.
* `GrantedAccess` is one of the following values:

  * `0x1010`
  * `0x1410`
  * `0x1438`
  * `0x143a`
  * `0x1fffff`
* `SourceImage` is excluded when it ends in:

  * `\svchost.exe`
  * `\wininit.exe`
  * `\services.exe`
  * `\lsass.exe`

These `GrantedAccess` values are Windows process access-right hex codes corresponding to `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` and related combinations — in plain terms, "read this process's memory." That's the specific capability Mimikatz-style credential dumpers request, which is why it's the detection signal rather than any process access to lsass.exe at all.

The resulting Splunk SPL conversion is:

```text
EventID=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff") NOT (SourceImage IN ("*\\svchost.exe", "*\\wininit.exe", "*\\services.exe", "*\\lsass.exe"))
```

The Sigma rule was validated successfully with 0 errors, 0 condition errors, and 0 validation issues.

## Validation

- Tested against: `sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx`
- Result: 1/1 match, HIGH severity
- ATT&CK technique: T1003.001
- Events processed: 1
- Detections: 1 HIGH
- Rule coverage: 1/1 rules matched (100%)
- SourceImage observed: `C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe`

The detected event had:

- EventID: `10`
- SourceImage: `C:\Users\IEUser\Desktop\mimikatz_trunk\Win32\mimikatz.exe`
- TargetImage: `C:\Windows\system32\lsass.exe`
- GrantedAccess: `0x1010`

The event's call trace also contains references to `mimikatz.exe`. The detection therefore successfully identified the expected LSASS memory-access event in the supplied Mimikatz test log.

## False Positive Considerations

Legitimate Windows processes may access LSASS during normal system operation, so detecting every process that accesses `lsass.exe` could generate false positives.

The rule excludes several known Windows system processes:

- `svchost.exe` — commonly hosts Windows services and may legitimately interact with system processes.
- `wininit.exe` — a core Windows initialization process that may legitimately interact with LSASS.
- `services.exe` — manages Windows services and may legitimately access system processes.
- `lsass.exe` itself — self-access is excluded because the rule is intended to identify another process accessing LSASS.

One category not covered by these exclusions: EDR/AV agents (for example, CrowdStrike or Defender ATP) also legitimately read lsass memory for monitoring purposes. This rule does not exclude them, so any deployment would need environment-specific tuning to add the organization's actual security tooling to the exclusion list.

These exclusions reduce expected noise while retaining suspicious LSASS access from other processes.

## Portability

The Sigma rule was successfully converted to Splunk SPL using the Sysmon processing pipeline.

The converted query is stored in:

`converted-queries/t1003_lsass_memory_access_splunk.spl`

The Splunk query preserves the original detection logic by identifying Sysmon Event ID 10 events targeting `lsass.exe`, checking for the specified `GrantedAccess` values, and excluding the specified legitimate process sources.
