# T1003.001 — LSASS Memory Access

This one was a good first rule because the logic is simple enough to understand and the event data makes sense. It is basically about a process reading LSASS memory, which is a very classic credential-dumping behavior.

The important bit was realizing that not every process access to LSASS is suspicious. A lot of Windows system processes do touch LSASS, so the rule needs to narrow it down to the kind of access that looks like memory dumping rather than normal service behavior.

## What I was looking for

The rule mostly watches process-access events where the target is LSASS and the granted access rights look like memory read access, not just general process interaction. The values like 0x1010 and 0x1fffff are the giveaway. That is the code path Mimikatz-like tools use when they want to pull credentials out of memory.

I also filtered out processes like svchost, wininit, services, and LSASS itself because those are expected system processes and would otherwise create a lot of noise.

## Validation

I tested it against the LSASS memory sample and it matched exactly once. The source was a Mimikatz-style process and the target was LSASS. That made the result feel real, because the event looked like the exact kind of behavior the rule is meant to catch.

The main thing I learned here is that the specific access right matters more than just seeing LSASS in the target field. If you only look for LSASS, you get a ton of false positives. The real signal is the memory-read behavior.

## False positives and caveats

This is one of those detections that can still get noisy in a real environment because EDR and AV tools legitimately inspect LSASS for security reasons. So I would not trust this by itself in production. It is a strong signal, but it still needs the usual context around process ancestry, user context, and what else was happening at the time.

## Portability

I also converted it into Splunk to make sure the same logic could be expressed outside Sigma. The conversion kept the same core idea: look for LSASS access events with suspicious granted access and exclude known system processes.

This was one of the first rules where I started seeing how detection logic and telemetry logic are really connected. The rule is not just a pattern. It is a choice about which events are meaningful and which ones are normal system noise.
