# T1059.001 — Suspicious PowerShell

This one was a good example of why detection engineering is not just writing a list of keywords. I started with a bunch of obvious PowerShell flags, and then I found out one of them was messing up the whole rule.

## What I originally thought

I wanted to catch suspicious PowerShell execution patterns like encoded commands, hidden windows, download strings, and IEX. That is a common attacker behavior and it is easy to understand.

The first version included a bunch of indicators, including -nop. That looked harmless at first because -nop is a real PowerShell flag, but it turned out to be a bad choice because it is also a substring inside -NoProfile.

## The bug that showed up later

This was a really useful bug to catch. The rule matched a bunch of benign PowerShell commands because -nop appeared inside a longer argument, -NoProfile. That meant the rule was matching strings that were not actually the suspicious flag I wanted.

It was not a Sigma syntax problem. It was a logic problem caused by using a broad string match on a short substring. The lesson here is that command-line detection is full of tiny traps like this.

## What I changed

I removed the -nop indicator and kept the rule focused on the more clearly malicious patterns. The final version still catches encoded commands, hidden execution, download strings, and IEX patterns, but it is much less likely to flag normal PowerShell behavior.

This was one of the moments where I realized that an alert is only useful if it catches what you want and not a bunch of harmless script noise.

## Validation

When I reran it, the rule still matched the suspicious samples I expected, but the false positive count dropped. It matched the suspicious PowerShell execution patterns in the dataset without the noisy benign cases.

One sample was especially interesting because it was a testing script designed to mimic attacker behavior in a safe environment. That showed me a subtle point: a command line can look malicious and still not be malicious by intent. The rule itself was doing what it was supposed to do, but context still matters.

## False positives

This is a classic example of a rule that needs context. PowerShell is used all the time by admins, deployment tools, and software automation. If I saw a hit, I would want to check who spawned it, where the parent process came from, and whether the command line was part of a legitimate admin workflow or a suspicious payload.

## Portability

I converted it to Splunk as well. The logic transferred fine, and the bigger takeaway was the same as before: string matching is powerful, but it needs to be careful and specific.
