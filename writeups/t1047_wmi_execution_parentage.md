# T1047 — WMI Parentage Rule

This one was a good reminder that the best detection is often not the obvious process itself but the relationship between processes. WMI Provider Host is a normal Windows process, but when it becomes the parent of a suspicious child process, that is more meaningful.

## What I was trying to catch

The main idea is that WMI can be abused for remote execution or local execution using tooling like WMIexec and PowerShell WMI commands. The suspicious event is not just seeing WmiPrvSE.exe running. It is seeing a child process created under WmiPrvSE.exe.

That is why the rule targets the parent image relation rather than the WMI service itself.

## Detection logic

The rule looks for a process creation event where the parent process is WmiPrvSE.exe. Then I filtered the obvious self-spawn cases like wmiprvse and conhost so that normal internal WMI activity does not create noise.

This is a typical example of a detection that is good only if you understand the baseline. WMI is used by legit admin tools too, so if I had just matched on the parent process alone the rule would have been much noisier than it needed to be.

## Validation

This rule produced a higher hit count than some of the narrower LOLBAS detections, which makes sense. WMI execution is broad and can be done through different tools that all end up producing a similar parent-child pattern. So the hit count was not surprising once I saw the actual process lineage.

The main thing I took from this was that a higher match count does not automatically mean a bad rule. In this case, the pattern is common enough that a wider family of execution methods converges on the same telemetry signature.

## False positives

This is still not a clean malicious signal by itself. SCCM, admin tools, and monitoring frameworks use WMI all the time. So I would not treat WMI parentage as definitive proof of malicious behavior. It is a useful signal that should be correlated with the child process, command line, user context, and host role.

## Portability

I converted it to Splunk without much trouble, and it kept the same logic. That is the kind of detection that works well once you understand the relationship and not just the process names.
