# T1087 and T1069 — Account and Group Discovery

This was one of the best examples of a rule failing for the right reason. I first wrote the Sysmon version because it seemed obvious: if an attacker is enumerating accounts and groups, they will probably run net.exe, whoami.exe, or similar commands.

But the dataset had other ideas.

## The first rule and the problem

The first rule looked for the process-creation events I expected. I ran it and got zero hits. That was annoying because I knew the data set had account and group discovery in it.

The clue was that the discovery activity clearly existed in files named around 4798 and 4799, which are Windows Security events, not Sysmon process creation events. The rule was valid as a Sysmon rule, but it was looking at the wrong telemetry layer for this dataset.

This was the point where I stopped treating validation as a single pass and started treating it as part of debugging the actual telemetry path.

## The real lesson

The evidence was present, but it was stored in the Security log rather than captured as a process command. So I wrote a second rule that targeted Event IDs 4798 and 4799 in the Windows Security audit pipeline.

That made the difference. The companion rule matched the missing discovery activity and confirmed the issue was not logic failure in the first place. It was a logSource mismatch.

This was a big realisation for me: a good Sigma rule still fails if it is looking at the wrong telemetry source.

## Validation

The Windows audit rule matched the relevant account and group discovery events. That confirmed the idea and closed the gap.

## False positives

There is some legitimate admin activity in this area too. IT staff often review user groups or account membership. So this is not a one-to-one malicious signal. It works best when correlated with the wider context.

## Overall takeaway

This rule set taught me that detection engineering is not just writing a good expression. It is also figuring out which telemetry actually contains the behavior you care about. That was probably the most important lesson in the whole project.
