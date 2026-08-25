# T1087 and T1069 — Account and Group Discovery

This one was one of the best examples of a rule failing for the right reason. I first wrote the Sysmon version because it looked obvious: if an attacker is enumerating accounts and groups, they are probably going to run `net.exe`, `nltest.exe`, or `whoami.exe`.

The issue was that the dataset had different ideas.

## The First Rule and the Problem

I built the Sysmon rule and ran it, and it gave me zero hits. That was annoying because I knew the discovery activity was in the dataset somewhere.

The clue was the filenames and Event IDs. The relevant evidence was showing up as 4798 and 4799, which are Windows Security events, not Sysmon process-creation events. The rule itself was not necessarily wrong, but it was pointed at the wrong telemetry layer for this dataset.

That was the point where I stopped treating validation like a single pass and started treating it like debugging the actual data flow.

## The Real Lesson

The evidence existed, but it was stored in the Security log rather than being recorded as a process command. So I added a second rule targeting Event IDs 4798 and 4799 in the Windows audit pipeline.

That second rule matched the missing activity, and it confirmed the real problem: not a logic failure, but a log source mismatch. A valid Sigma rule can still miss everything if it is looking at the wrong telemetry source.

## Validation

The Windows Security rule eventually matched the relevant account and group discovery events. That closed the gap and confirmed the hypothesis.

## False Positive Considerations

There is legitimate admin activity here too. IT staff often enumerate users and groups for maintenance or troubleshooting. So this is not a one-to-one malicious signal by itself. It works best when correlated with the host, the user, and the wider surrounding event chain.

## Overall Takeaway

This rule pair taught me one of the most important lessons in the whole project: detection engineering is not just about writing a good expression. It is also about knowing which telemetry actually contains the behavior you are trying to detect.
