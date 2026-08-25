# T1112 — Registry Run Key Persistence

This one is a pretty classic persistence technique. You add something to the Run or RunOnce keys and Windows executes it automatically when the user or system starts up.

I liked this one because it is a very clear example of persistence that does not need to be hidden in a weird place. It is right there in the registry, which is why the detection is so straightforward.

## What I was looking for

The rule focuses on registry modifications under the common startup persistence hives. That is the actual persistence layer. The event itself is not necessarily suspicious unless the value points to something unexpected or malicious.

That is also why this kind of detection should be correlated with the executable path and the user context. A normal software update or legitimate app might write to the same registry areas.

## Validation

The dataset produced the expected kind of hits for this technique. They lined up with the idea that something was being added to run at startup, which is exactly the behavior the rule is meant to catch.

## False positives

This is one of those detections where a lot of legitimate software touches the same keys. Installers, management tools, and vendor software can also add Run entries. So I would not treat a match as definitive proof of malware by itself.

## Extra note

There was an ATT&CK tag warning in Sigma validation, but it looked cosmetic rather than a real logic issue. The rule itself was still doing the detection work it was intended to do. That was a useful reminder that tooling metadata issues and detection logic are not always the same thing.
