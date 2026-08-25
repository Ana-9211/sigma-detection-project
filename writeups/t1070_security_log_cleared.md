# T1070.001 — Event Log Clearing

This one is pretty straightforward in concept but kind of tricky in interpretation. The attacker clears security logs to remove evidence. That is a classic anti-forensics move, so this rule is meant to catch the event where the Windows Security log itself was cleared.

## What I was looking for

The rule is based on Windows Security Event ID 1102. That is the event that records the Security log being cleared. It is not a Sysmon event. It belongs to the Windows audit pipeline, which is exactly the thing I had to remember when I was testing it.

This is a good example of why I stopped assuming every detection should use Sysmon. Sometimes the evidence is in the security log, not in process creation telemetry.

## Validation

It matched 24 hits in the attack sample set. That number looked high at first, but the dataset is a collection of attack scenarios and repeated test-environment log resets can easily inflate the count. So I did not treat every hit as a separate malicious action. I treated it as a valid signal that Event ID 1102 appeared in the dataset.

That was an important mindset change for me. A high hit count is not automatically meaningful until you think about the dataset context.

## False positives

This can happen during legitimate admin maintenance, log rotation, troubleshooting, or lab resets. So I would not call it a malicious alert by itself. In production, I would correlate it with the account that cleared the log, the host, the time window, and the surrounding events.

## Portability

The rule converted into Splunk using the Windows audit pipeline. It was one of the clearer examples of a detection that depends on the correct telemetry layer rather than on the rule expression alone.
