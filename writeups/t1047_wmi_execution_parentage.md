# T1047 — WMI Execution via WmiPrvSE Parentage

This one was a good reminder that the best detection is often not the obvious process itself, but the relationship between processes. WmiPrvSE.exe is a normal Windows component, but when it becomes the parent of a suspicious child process, that is a much more interesting signal.

## Technique

WMI can be abused for execution and lateral movement. Tools like WMIexec, PowerShell WMI cmdlets, and native WMI usage can all create a process under the WMI Provider Host, which is exactly what this rule is trying to catch.

## Detection Logic

The rule is built around process creation where the parent image is WmiPrvSE.exe. I also filtered out the obvious self-spawn cases like wmiprvse and conhost so it does not get buried in normal internal WMI activity.

That was the important part. If I had simply alarmed on WmiPrvSE.exe alone, the rule would have been noisy because WMI is used by legitimate systems management tooling too.

## Validation

This was one of the higher-volume detections in the project. That actually made sense once I looked at the process lineage. WMI execution can be done through a few different tools and methods, and they all end up creating a similar parent-child pattern sometimes.

So the high count was not necessarily a sign that the rule was too broad. It was more a sign that WMI execution is a reusable pattern across multiple attack tooling variants.

## False Positive Considerations

This is still not a “prove malware” signal by itself. SCCM, monitoring agents, and admin tooling use WMI all the time. That means I would never treat WMI parentage as definitive malicious behavior without checking the child process, command line, user, and host context.

## Portability

It converted into Splunk without much trouble, and the logic remained the same. This was one of those detections where understanding the parent-child relationship is more important than memorizing the process name itself.
