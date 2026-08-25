# Mistakes and fixes

This file is meant to capture the mistakes I made while building the Sigma detections, because those mistakes ended up being the best part of the learning process.

A rule can look correct on paper and still fail in practice. This is where the real learning happens.

## 1. Wrong log source assumption

One of my first mistakes was assuming that a technique would appear in a single obvious log source. In practice, Windows telemetry can split across:

- Windows Security
- Sysmon
- PowerShell operational logs
- Task Scheduler logs
- related process and command-line sources

I learned that the rule must match the actual source of the signal, not the source I expected from a blog post or a generic detection template.

### Fix

Before writing a rule, I now check:

- which log source contains the relevant event
- which field usually carries the attacker behavior
- whether the detection is actually visible in the data I am testing against

This is a good example of how detection engineering is not just YAML work. It is data interpretation.

## 2. Field mismatch and incorrect assumptions

I also learned that the field names in a Sigma rule do not always match what the event data looks like in a real sample. Some detections were valid in structure but wrong in behavior because the fields I chose did not map to how the inputs were actually recorded.

This caused me to re-check the event schema instead of trusting the abstract logic.

### Fix

I started validating more carefully against the actual telemetry and checking whether the event was using:

- the correct process field
- the correct parent-child relationship
- the correct log channel
- the correct command-line or object field

## 3. Parentage confusion

A lot of the detections I wrote depended on understanding parent-child relationships between processes. I initially assumed the relationship I wanted existed in the telemetry, but in some cases the behavior was split across multiple event types or different levels of ancestry.

That meant a rule could appear logically sound but still fail to detect the behavior correctly.

### Fix

I now treat process lineage as a thing to validate, not a thing to assume.

I check:

- whether the parent process is visible in the event itself
- whether the event is capturing the originating binary or the child action
- whether there are events from a different source that show the relationship more clearly

## 4. Over-broad logic and noisy rules

A rule that matches everything is easy to write. A useful rule is much harder.

I had a few cases where the logic was broader than intended, which created noise and made the detection less actionable. This taught me that valid syntax is not the same as useful detection.

### Fix

I started narrowing the rule logic based on:

- specific process names
- required command-line patterns
- suspicious parent-child combinations
- relevant security events instead of generic process execution

## 5. The "looks good" problem

Some detections looked strong in a Sigma editor and looked convincing in my notes, but they did not behave correctly when applied to a sample dataset. That was one of the most important lessons in the project.

The issue was not always the detection logic itself. It was usually the mismatch between how I thought the event was represented and how the data was actually recorded.

### Fix

My rule-writing process now includes:

1. identify the event source
2. validate the field names in the sample data
3. test the rule against known examples
4. inspect false positives and missed detections
5. revise the logic only after checking the data again

## 6. Why this matters

This project is useful because it documents the fact that detection engineering is iterative. A good rule is not just a static object. It is a result of repeated testing, correction, and re-evaluation.

The mistakes were valuable because they showed me how easy it is to be wrong even when the logic looks reasonable.

## 7. The big takeaway

I do not treat detections as finished just because the YAML parses correctly.

A detection is only useful when it matches the actual telemetry in meaningful ways.

That is the main lesson I want to carry forward.
