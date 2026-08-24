# T1059.001 — Suspicious PowerShell Execution

## Technique

This rule detects suspicious PowerShell execution involving obfuscation, encoded commands, hidden execution, and download cradles. These techniques are commonly used to conceal PowerShell activity or retrieve and execute second-stage payloads.

## Detection Logic

The rule targets Sysmon Event ID 1 (Process Creation) and requires both:

1. `Image` to end with `\powershell.exe` or `\pwsh.exe`
2. `CommandLine` to contain one of the suspicious indicators:

   * `-enc`
   * `-EncodedCommand`
   * `-w hidden`
   * `-windowstyle hidden`
   * `IEX`
   * `DownloadString`
   * `Invoke-Expression`
   * `Net.WebClient`

An earlier version of the rule also included `-nop` as an indicator. During testing, this indicator was removed because of a substring collision with `-NoProfile` — a completely benign, extremely common PowerShell flag. Since `-nop` is a literal substring of `-NoProfile`, the `contains` modifier matched it, producing 2 false-positive hits out of the original 6. This is an important limitation of broad `CommandLine|contains` matching: short indicators can match legitimate longer arguments.

The final rule was validated successfully with 0 errors, 0 condition errors, and 0 validation issues.

## Validation

* Tested against: Full `EVTX-ATTACK-SAMPLES` repository
* Files processed: 278
* Events processed: 1,501
* Result: 4 HIGH-severity hits across 3 files (down from 6 before the `-nop` fix)
* Rule coverage: 1/1 rules matched (100%)

### File 1 — IIS discovery
`discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx`

PowerShell spawned from `w3wp.exe` (IIS worker process), with an encoded command containing a real payload. PowerShell execution originating from an IIS worker process, combined with encoded command content, is an unusual process relationship and execution pattern consistent with a web-shell-driven attack.

### File 2 — EDR Testing Script
`panache_sysmon_vs_EDRTestingScript.evtx`

The command line matched the suspicious PowerShell pattern (`Net.WebClient` + `IEX`), but the underlying tool is [op7ic/EDR-Testing-Script](https://github.com/op7ic/EDR-Testing-Script), a public tool built specifically to safely reproduce attacker-like command-line patterns for testing detection tooling.

> The detection is a true positive for the behavioral pattern, but the underlying activity is benign by intent.

This demonstrates why command-line detections should not automatically be treated as proof of malicious activity.

### File 3 — PsExec/Meterpreter
`LM_sysmon_psexec_smb_meterpreter.evtx`

2 detections. PowerShell execution associated with a PsExec/Meterpreter sequence, using a gzip/base64-compressed loader launched via `cmd.exe /b /c start /b /min powershell.exe -nop -w hidden -noni -c ...`.

## False Positive Considerations

The main false-positive issue discovered during validation was the `-nop` / `-NoProfile` substring collision, described above. The fix was to remove `-nop` from the indicator list rather than attempt to special-case every `-NoProfile` invocation.

There is also an important distinction demonstrated by `panache_sysmon_vs_EDRTestingScript.evtx`: an EDR-testing tool can intentionally reproduce attacker-like PowerShell patterns. The rule correctly identifies the pattern, but the event can still be benign in context.

Legitimate administrative scripts, scheduled tasks, deployment systems, and configuration-management tools can also invoke PowerShell with unusual command-line arguments. Consequently, the detection should be investigated alongside process ancestry, user context, execution location, and surrounding events rather than treated as definitive proof of malicious execution.

## Portability

The Sigma rule was successfully converted to Splunk SPL using the Sysmon processing pipeline:

```text
sigma convert -t splunk -p sysmon rules/t1059_suspicious_powershell_execution.yml > converted-queries/t1059_suspicious_powershell_execution_splunk.spl
```

The resulting SPL preserves the core detection logic: identify PowerShell process creation events and match suspicious command-line indicators.
