# T1548.002 — UAC Bypass via Auto-Elevate Binary Parentage

This one was one of those detections that took a bit of mental reorientation. At first glance, I was thinking “this is just a normal Windows binary doing a normal Windows thing,” but the interesting part is the parent-child relationship. A trusted auto-elevate binary spawning a shell is exactly the sort of thing attackers abuse.

## Technique

This is a User Account Control bypass technique. It usually involves a child process like `cmd.exe` or `powershell.exe` being spawned from a known auto-elevate binary such as `fodhelper.exe`, `eventvwr.exe`, or `sdclt.exe`.

## Detection Logic

The rule does not just look for the binary name. It specifically looks for the parent-child chain: an auto-elevate binary acting as the parent of a command shell or PowerShell process.

That is the actual signal. If I just checked for `fodhelper.exe` or `eventvwr.exe`, I would get a lot of false positives because those binaries exist for legitimate reasons. The parentage is what makes the activity suspicious.

## Validation

I tested it against the full EVTX sample set and got 6 hits. That was a good result because the dataset contained a large UACME family of samples, but only a subset of them used this exact parent-child pattern. So the rule is not claiming to catch every UAC bypass, only the ones using this specific auto-elevate mechanism.

This was a nice reminder that coverage does not have to mean “every variant of every technique.” A good detection just needs to match the exact behavior it is designed to catch.

## False Positive Considerations

This is usually a rare pattern in normal enterprise environments, which is why it is high-value. The auto-elevate binaries in the rule do not normally spawn shells as child processes. That makes a match worth investigating.

## Portability

This converted into Splunk using the Sysmon pipeline without much trouble. It is a solid example of using parent-child process logic to detect abuse of built-in Windows behavior rather than trying to catch everything with a broad, noisy rule.
