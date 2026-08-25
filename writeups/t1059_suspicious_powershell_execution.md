# T1059.001 — Suspicious PowerShell Execution

This one was a good example of why detection engineering is not just “write a list of common attacker strings and hope for the best.” I started with a bunch of obvious PowerShell flags and then found out one of them was actually making the rule worse.

## Technique

This covers PowerShell-based execution that is often used for obfuscation, encoded commands, remote content, or script execution. Attackers like PowerShell because it is built into Windows and usually has enough access to do a lot of malicious work without dropping a totally obvious binary.

## Detection Logic

The rule looks for suspicious execution patterns like encoded commands, hidden execution flags, download-related command strings, and IEX usage. I was trying to catch the normal indicators that show up in malicious scripts.

The bug was that I had included a `-nop` check. At first it looked harmless because `-nop` is a real PowerShell switch, but it is also a substring inside `-NoProfile`. That meant the rule could match the wrong command lines and create noise. It was not a syntax error, just a logic issue caused by loose substring matching.

I removed that part and narrowed the detection back down to the clearer malicious patterns. That ended up making the rule more reliable.

## Validation

After the fix, the rule still matched the suspicious files I expected, but the false positives dropped. The dataset included a real testing script that was intentionally mimicking attacker behavior in a safe environment. That was a good reminder that “looks malicious” does not always mean “is malicious.” The pattern can still be benign by intent, even if the command line is suspicious enough to trigger the rule.

## False Positive Considerations

PowerShell is everywhere in enterprise environments. Admins, software deployment tools, maintenance scripts, and internal tooling all use it. So a hit is not enough on its own. I would check the process tree, who launched it, what the parent process was, and whether the command line fit a legitimate workflow or a suspicious payload.

## Portability

I converted it to Splunk as well. The logic translated fine, but the real lesson was more important than the conversion: command-line detection is easy to overfit if the indicators are too broad or too clever.
