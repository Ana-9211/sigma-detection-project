# T1055 — CreateRemoteThread Injection

This one was one of the more interesting rules because it showed me that a rule can look correct and still be wrong in a subtle way. I thought I had the filters sorted, but then I caught a bug in how the source and target fields were compared.

## Technique

CreateRemoteThread injection means one process creates a thread inside another process. That is a pretty classic way to run code in someone else's memory space, which is exactly what attackers do when they are trying to hide or make their code blend in.

I was watching Sysmon Event ID 8 for that pattern. The suspicious part is not just that a thread was created, but that something like PowerShell created a thread inside a user process like notepad.

## Detection Logic

The rule looks at Event ID 8 and then checks the source and target process relationship. I had two filter blocks. One excluded known system processes like svchost, services, wininit, and MsMpEng. The other was meant to exclude self-spawns by comparing SourceImage and TargetImage.

The problem was that the original comparison was not actually comparing the two fields properly. It was using a literal comparison instead of field-to-field comparison, which meant the logic did not behave the way I thought it did. That is exactly the kind of bug that slips through if you only trust the Sigma validation output and do not inspect the raw event fields.

I fixed it by using the proper fieldref logic so Sigma compares SourceImage to TargetImage correctly. This was one of those moments where the validation pass told me nothing useful until I looked deeper at the data.

## Validation

I tested the rule against the Meterpreter reflective PE injection sample and it matched 9 events. The source was PowerShell and the target was notepad. That is a strong signal because notepad has no real reason to be receiving threads from PowerShell.

The important thing was that all 9 events shared the same source and target process GUIDs. They were part of one continuous injection chain, not nine unrelated events. That made the detection feel much more real and much less like random noise.

## False Positive Considerations

This one definitely has a false positive risk. Debuggers, EDR tooling, and some legitimate admin applications can create remote threads too. That is why the exclusion list matters and why I would still want to check the context before calling it malicious.

The rule is not saying every remote thread is malicious. It is saying a cross-process thread creation relationship that matches the suspicious pattern deserves investigation.

## Portability

I converted the rule to Splunk as well. The converted query kept the same logic, but the bigger lesson was the field comparison bug. That was the kind of mistake that would not have been caught unless I actually looked at the event structure and reasoned about what the rule was doing.
