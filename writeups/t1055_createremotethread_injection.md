# T1055 — Process Injection via CreateRemoteThread

## Technique

CreateRemoteThread injection occurs when one process creates a thread that executes code within the memory space of another process. Attackers can abuse this mechanism to execute malicious code under the context of a legitimate process, helping them evade detection and blend malicious activity into a trusted process.

## Detection Logic

The rule looks for Sysmon Event ID 8, which records CreateRemoteThread activity. The primary selection is therefore:

```yaml
selection:
    EventID: 8
```

Two separate filter blocks are used to remove expected activity:

- `filter_knownsource` excludes known legitimate source processes such as `svchost.exe`, `services.exe`, `wininit.exe`, and `MsMpEng.exe`.
- `filter_self` excludes self-process activity by comparing `SourceImage` with `TargetImage` using Sigma's field-reference modifier:

```yaml
filter_self:
    SourceImage|fieldref: TargetImage
```

The field-reference modifier is important. An earlier version used:

```yaml
SourceImage: 'TargetImage'
```

which does not compare the two fields. It checks whether `SourceImage` literally contains the string `TargetImage`, so it would silently fail to identify self-process relationships. Using `|fieldref` performs the intended field-to-field comparison.

The condition was refined twice during development:

```yaml
condition: selection and not filter_knownsource and not filter_self
```

An earlier version used `selection and not 1 of filter_*`, which is logically equivalent (both filters are OR'd together for exclusion), but the Splunk backend could not convert an OR'd field-reference comparison. Rewriting the condition using De Morgan's Law — `not (A or B)` is equivalent to `(not A) and (not B)` — produced identical detection logic while avoiding the unsupported OR/fieldref combination during Splunk conversion.

## Validation

- Tested against: `test-logs\EVTX-ATTACK-SAMPLES\Execution\Sysmon_meterpreter_ReflectivePEInjection_to_notepad_.evtx`
- Result: 9 hits
- SourceImage: `powershell.exe`
- TargetImage: `notepad.exe`

The detected events were not excluded by either filter. `powershell.exe` does not match the known legitimate source list, and it is different from `notepad.exe`, so the self-process filter does not apply.

The activity is suspicious because `notepad.exe` is an ordinary user application and receiving remote threads from a PowerShell process is an unusual process relationship. In the supplied test case, the filename identifies the scenario as a Meterpreter Reflective PE injection example.

All nine detected events shared the same `SourceProcessGuid` and `TargetProcessGuid` and occurred within approximately 15 milliseconds of one another. This indicates that the nine detections belong to the same source/target process relationship and represent a single injection sequence that created multiple remote threads, rather than nine unrelated injection attempts.

## False Positive Considerations

Legitimate software can use CreateRemoteThread for purposes unrelated to malicious injection. Potential false positives include:

- Debuggers that interact with another process during analysis.
- Monitoring or instrumentation tools.
- Certain installers or legitimate administrative software.
- EDR/AV products that inject into processes for security monitoring or instrumentation.

The rule therefore excludes several known legitimate source processes (`svchost.exe`, `services.exe`, `wininit.exe`, and `MsMpEng.exe`). The exclusion list should still be tuned for the specific environment because legitimate security products and other software may use remote-thread mechanisms that are not represented by these exclusions.

## Portability

The Sigma rule was converted to Splunk SPL using the Sysmon processing pipeline:

```text
sigma convert -t splunk -p sysmon rules/t1055_createremotethread_injection.yml > converted-queries/t1055_createremotethread_injection_splunk.spl
```

The resulting query is stored as:

`converted-queries/t1055_createremotethread_injection_splunk.spl`
