# T1055 — CreateRemoteThread Injection

This one was one of the more interesting rules because it taught me that rule logic can look correct and still break in a subtle way. I thought I had the filters right, but there was a bug in how I compared the source and target fields.

## What I was trying to detect

CreateRemoteThread injection is when one process creates a thread inside another process. That is a classic way to run code under someone else's memory space, which is exactly the kind of thing malware does to hide or blend in.

I was looking at Sysmon Event ID 8, which records this kind of remote thread creation. The suspicious part is not just that a thread was created. It is that a process like PowerShell or some other tool created a thread inside a normal user process such as notepad.

## The filter issue I had to fix

I had two filters in the rule. One excluded known legit source processes like svchost, services, wininit, and MsMpEng. The other tried to exclude self-process events by comparing SourceImage to TargetImage.

The problem was that I initially used a literal comparison instead of a field-to-field comparison. That meant the rule did not actually compare the two fields properly. It just checked whether the string looked similar instead of whether the values were equal.

The fix was to use the fieldref approach so that Sigma compares SourceImage and TargetImage correctly. This is the kind of mistake that would be easy to miss if I had only looked at the green validation output and not the actual raw event values.

## Validation

I tested the rule against the Meterpreter reflective PE injection sample and it matched 9 events. The source was PowerShell and the target was notepad. That is the kind of process relationship that stands out.

The most important thing was the fact that all 9 events shared the same source and target process IDs. They were part of one injection sequence, not 9 separate random events. That made the pattern much more believable.

## False positives

This one definitely has a false positive risk. Debuggers, EDR, and some admin tools can create remote threads for legitimate reasons. That is why I excluded a few known system processes and why the rule should still be used with context.

The thing I learned here is that the rule is not trying to say a remote thread always means malware. It is trying to flag a suspicious relationship that deserves investigation.

## Portability

I converted the rule to Splunk as well. The logic still held up in the converted form, which was useful, but the bigger lesson was the field comparison bug. That was the kind of mistake that would not have been caught by just trusting the output.
