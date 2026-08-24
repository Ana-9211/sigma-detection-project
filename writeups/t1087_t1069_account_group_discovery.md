# T1087/T1069 — Account and Group Discovery

## Technique
Account and group discovery is a core Windows discovery technique used to identify local user accounts, groups, memberships, and trust relationships. Attackers use this to understand privilege boundaries, target lateral movement, and find weak or highly privileged accounts.

## Detection Logic — Rule A (Sysmon)
The first rule attempts to catch account and group discovery by monitoring command-line execution of discovery tooling such as `net.exe`, `whoami.exe`, and related account enumeration utilities. This approach is valid when the telemetry is captured via process creation events and the command line contains the enumeration pattern.

In practice, the rule logic is designed to match the sequence of commands that reveal local users and groups, such as enumeration of users, groups, and security policy information.

## Validation — Rule A
The Sysmon-based rule returned 0 hits across the validation set, which was investigated rather than accepted as a pass. At face value, that outcome suggested the rule was logically fine but likely not aligned with the actual evidence source available in the dataset.

## The Gap
The key problem was not a bad Sigma expression; it was a telemetry mismatch. The dataset contained evidence for local group and account enumeration in files such as `4798` and `4799` Security log events, but those events never reached the Sysmon process-creation rule path. The validation process confirmed that the rule saw zero relevant events because the log source itself was filtered before matching occurred.

The debug output showed the concrete issue: `Total events processed: 0` for the rule path under the Sysmon pipeline. In other words, the relevant evidence existed, but in a different telemetry layer. This invalidated the assumption that the technique was simply absent; it was present in the dataset but captured through Windows Security auditing, not through Sysmon process creation.

## Detection Logic — Rule B (Windows Security Auditing, companion rule)
A companion Sigma rule was therefore written for Windows Security auditing, specifically targeting Event IDs 4798 and 4799. These events document local group enumeration and group membership discovery in the Security log and map directly to the attacker behavior in this dataset.

This is a necessary split because Sigma rules are constrained by log source. One technique can legitimately require multiple rules when the relevant evidence is split across different telemetry sources.

## Validation — Rule B
The Windows Security auditing rule produced 8 hits, including the files that the original Sysmon rule missed entirely. This confirmed the hypothesis and closed the coverage gap. The result was not a random improvement; it validated a real, data-driven diagnosis.

## Lesson
A green Sigma validation result cannot tell you whether the required evidence is actually present in your data. This case demonstrates a larger principle of detection engineering: the correct telemetry source matters as much as the detection logic itself. When the dataset is built around a different log source, the rule must follow the evidence — not the assumptions.

## False Positive Note
The primary false positive risk is legitimate administrative account review, security auditing, and internal help-desk enumeration. That is manageable by correlating with the context of active user behavior, maintenance windows, or approved IT workflows.

## Outcome
This is the strongest example in the project of a detection gap being diagnosed and closed through evidence rather than guesswork. It shows that understanding the dataset, telemetry source, and log pipeline is often the real difference between a ruleset that looks complete and one that is actually operationally useful.
