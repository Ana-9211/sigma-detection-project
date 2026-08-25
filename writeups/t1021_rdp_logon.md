# T1021.001 — RDP Logon

This one was useful because it showed me that a detection can be technically correct and still not be a strong alert on its own. RDP is a real attack technique, but it is also a normal admin feature. So the rule is really more of a visibility signal than something that screams malicious by itself.

## What the rule is trying to catch

The main event here is a successful Windows logon, but I narrowed it to LogonType 10, which is the RemoteInteractive type used for RDP. That is the part that actually distinguishes RDP from normal interactive or service logons.

I used the Windows Security audit pipeline for this one because Event ID 4624 belongs there, not in Sysmon process creation.

## Why this was a learning moment

At first I thought the rule would just be "logon happened, alert". But when I actually tested it, there were 87 successful logon events in the dataset and only 2 of them were RDP. That was the key finding. The LogonType filter was doing real work, and it was excluding a whole bunch of non-RDP logons that otherwise looked similar.

That made me realize that a lot of detections are not about matching one obvious event. They are about filtering out all the normal variants so the suspicious one stands out.

## Validation

When I ran the rule, it matched 2 events. That is a low number, but that fits the nature of this technique. It is not a noisy indicator in the same way as PowerShell or WMI execution. It is more of a contextual signal that someone used RDP.

## False positives

This is a big one. RDP is common in real environments. IT admins, remote jobs, support staff, and managed devices all use it. So if I saw a hit, I would not treat it as a direct malicious alert without checking source IP, host, time of day, and whether that machine is expected to use RDP.

## Portability

The Sigma rule converted cleanly into Splunk using the Windows audit path. That part was straightforward, but again, the important lesson is not just conversion. It is understanding that the detection is useful only when paired with context.
