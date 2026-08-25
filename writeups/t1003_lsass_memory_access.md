# T1003.001 — LSASS Memory Access

This was a pretty good first rule because the logic is simple enough to understand and the event data actually makes sense. The idea is that a process is reading LSASS memory, which is one of the classic credential-dumping behaviors.

I had to keep reminding myself that not every LSASS access is malicious. A lot of Windows system processes touch LSASS for legitimate reasons, so the rule needs to be narrower than just “target is LSASS”. The real signal is the memory access pattern and the process doing it.

## Technique

This is basically the credential-dumping path. If a process reads memory from LSASS, it is usually trying to pull secrets out of the Windows authentication process. That is exactly the kind of behavior Mimikatz-style tooling uses.

## Detection Logic

The rule watches for process access events where the target is LSASS and the granted access rights look like memory read access instead of normal service interaction. The values like 0x1010 and 0x1fffff are a big clue here. They are not normal read operations for an everyday system process.

I also excluded a few expected Windows processes like svchost, wininit, services, and LSASS itself. Otherwise the rule would be drowning in noise from normal OS behavior.

## Validation

I tested it against the LSASS memory sample and it matched exactly once. The source process looked like a credential-dumping tool and the target was LSASS. That was the moment it felt real, because the sample matched the behavior the rule was meant to capture.

This also taught me the main lesson for this technique: the access rights matter more than the target name alone. If I only looked for LSASS, the rule would instantly become useless because lots of Windows internals touch it.

## False Positive Considerations

This one still has a real caveat in real environments because EDR, AV, and some security tooling legitimately inspect LSASS memory. So I would not treat an LSASS access alert as automatic malware by itself. It is a strong signal, but it still needs context such as the process name, parent process, user, and what else was happening around the event.

## Portability

I also converted it into Splunk so I could check whether the same logic translated outside Sigma. The converted rule kept the same idea: look for suspicious LSASS memory access and filter out the known system noise.

This was one of the first times I saw how tied detection logic and telemetry logic really are. A rule is not just a string pattern. It is a deliberate decision about which events are meaningful and which ones are just normal system activity.
