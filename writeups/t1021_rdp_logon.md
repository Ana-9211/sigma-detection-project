# T1021.001 — Interactive Logon via RDP

This one was useful because it showed me that a rule can be technically correct and still not be a strong alert by itself. RDP is a real attacker technique, but it is also a normal administrative feature. That means the detection is more of a visibility signal than a flashing “malware detected” alarm.

## Technique

Remote Desktop Protocol is a classic lateral movement technique. Attackers use it when they already have valid credentials and want to move around a compromised environment or access a machine interactively.

## Detection Logic

The rule targets Windows Security Event ID 4624 and filters specifically for LogonType 10, which is the RemoteInteractive logon type used for RDP. That filter is important because there are a lot of successful logons that are not RDP at all.

I used the Windows audit pipeline for this one because Event ID 4624 is part of the Security log, not Sysmon. That mattered a lot when I was validating it.

## Validation

I ran it against the attack sample set and it matched 2 events. At first that seemed low, but it actually made sense. There were 87 total successful logon events in the dataset, but only 2 of them were LogonType 10. So the LogonType filter was doing real work and excluding all the other non-RDP logon types.

That was a good reminder that a lot of detections are not just “match the obvious thing.” They are also about filtering out the normal noise so the suspicious variant stands out.

## False Positive Considerations

This is a big one because legitimate admin work uses RDP all the time. IT support, remote workers, maintenance windows, and managed devices all create remote logons. So I would not take a hit as immediate malicious activity. I would check the source IP, the user, the host role, and whether that access pattern is expected.

## Portability

The Sigma rule converted cleanly into Splunk using the Windows audit path. The conversion itself was not complicated, but the real lesson was understanding that this rule is useful mostly as context and correlation, not as a standalone proof of compromise.
