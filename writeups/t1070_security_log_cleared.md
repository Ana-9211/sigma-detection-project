# T1070.001 — Clear Windows Event Logs

This is one of those detections that is conceptually really simple but still easy to misread. The idea is that an attacker clears the Windows Security log to remove evidence of what they did. That is anti-forensics, plain and simple.

## Technique

Clear Windows Event Logs is a classic way to destroy forensic trail. If somebody wipes the Security log, they are trying to hide logon activity, process execution, persistence, or anything else that would otherwise be visible to analysts.

## Detection Logic

The rule is built around Windows Security Event ID 1102, which is generated when the Security log is cleared. This belongs to the Windows audit pipeline rather than Sysmon, which was a useful thing to remember while I was validating it.

This is one of the clearest examples in the project of a rule where the actual telemetry source matters more than the detector logic itself. If I had used the wrong pipeline, I would have been chasing the wrong type of event.

## Validation

I tested it against the full EVTX attack sample set and got 24 hits. At first that looked like a lot, but the dataset is a collection of repeated attack scenarios and lab resets, so I did not assume each hit was an independent malicious cleanup. The important point was that the event was present and the rule caught it correctly.

That was a useful lesson in not overinterpreting high numbers without dataset context. A lot of detections in these sample corpora are not one-to-one with real-world incidents.

## False Positive Considerations

Administrators can legitimately clear or rotate logs during maintenance or troubleshooting. So I would not call this a malicious alert by itself. In a real environment, I would correlate it with who cleared the log, what host it was on, whether the action was expected, and what else happened around the same time.

## Portability

I converted it into Splunk using the Windows audit pipeline. It stayed clean and easy to understand, and it reinforced the same point as a few earlier detections: you have to pick the right telemetry source before the rule can be meaningful.
