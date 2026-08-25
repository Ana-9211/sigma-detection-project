# T1112 — Registry Run Key Persistence

This is a very standard persistence technique, and honestly it is one of the easiest ones to explain. The idea is that a program writes to a Run or RunOnce registry key so Windows launches it automatically during startup or logon.

## Technique

Registry Run Key persistence is pretty classic attacker behavior. It does not need to be hidden in a strange location. The persistence is simply placed in a known startup location and then the system executes it for the attacker.

## Detection Logic

The rule looks at registry-modification events and focuses on the startup persistence paths that matter. It is not a blanket “anything in the registry is suspicious” rule. It is only interested in the areas that are relevant to Run key persistence.

That is an important distinction because the registry is huge and a lot of legitimate software touches it. The question is whether the change matches a persistence pathway rather than just a generic registry write.

## Validation

The dataset produced hits that matched this persistence behavior, which is exactly what I expected. That made the rule feel solid because the detections lined up with the known attack pattern.

## False Positive Considerations

This is a major one. Legitimate installers, enterprise tooling, and vendor software often modify Run keys. A match by itself is not proof of malware. I would check the value name, the executable path, the parent process, the user context, and whether that software is expected on the machine.

## Extra Note

There was an ATT&CK tag warning from Sigma validation, but it looked cosmetic rather than an actual logic failure. The rule still evaluated correctly and the detection behavior was still valid. That was a useful reminder that tooling warnings and real detection quality are not always the same thing.
