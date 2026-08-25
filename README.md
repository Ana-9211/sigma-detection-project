# Sigma Detection Engineering Project

This project is one of the clearest examples of how I learn: I start with an idea, build a detection, test it against real telemetry, and then fix the assumptions that were wrong.

I wanted to understand how detections actually behave in the real world instead of treating Sigma like a syntax-only exercise. A lot of the learning here came from debugging the mismatch between what the rule looked like on paper and what the log source actually contained.

## What I was trying to learn

- how Windows attack techniques appear in Windows Security, Sysmon, and related telemetry
- why a rule can look valid but still fail because the wrong source or field is being used
- how to validate detections against public EVTX data instead of trusting the logic blindly
- how to reason about signal vs noise when a rule matches too much or too little

## Repo structure

- `rules/` — the Sigma rules I wrote or adjusted
- `converted-queries/` — Splunk queries generated from the Sigma rules
- `writeups/` — notes explaining the technique, validation, and mistakes
- `Zircolite/` — local validation workflow and tooling
- `test-logs/` — sample logs used during testing

## What I learned while building this

The biggest lesson is that detections are not just YAML logic. They are an interpretation of real telemetry.

A lot of my early mistakes were not Sigma syntax issues. They were understanding issues:

- the event was in Windows Security, not Sysmon
- the field name differed from what I assumed it was
- the rule matched the wrong parent/child relationship
- the logic was too broad because it used too much text matching instead of the correct event shape

That was the part that actually improved my thinking.

## Examples of mistakes I had to fix

### 1. Wrong log source assumptions
I initially assumed a technique would be visible in one log source, but the real evidence was in another. This taught me to validate the telemetry path before trusting the rule logic.

### 2. Field mismatch
Some detections looked good until I realized the actual data used a different field convention or a different event type than expected. This was a reminder that detection engineering is as much about data interpretation as it is about rule syntax.

### 3. False positives from weak logic
A rule can be syntactically valid and still be noisy. I learned that a lot of “good” detection logic breaks down when it is tested against real-world data that includes legit admin tasks, system noise, and edge cases.

### 4. Parentage and process lineage confusion
A lot of the work here involved understanding process lineage, parent-child relationships, and why a rule may appear sensible but still miss the actual behavior it is trying to catch.

## Why this project matters to me

This project helped me move from “I know Sigma syntax” to “I understand how detections behave in practice.”

That matters more than writing a perfect rule on the first pass.

## Current direction

I want to keep building on this by improving:

- rule quality and validation discipline
- telemetry reasoning
- false-positive reduction
- documentation of how a rule changed as I learned more about the dataset

## Learning notes

I keep the learning process visible in the repo because that is the real value of this work.

- what I assumed initially
- what the telemetry actually showed
- what I changed after testing
- what still needs work

This is documented in the project notes and writeups, especially in the deeper case-by-case rule explanations.

## Overall takeaway

The important thing I learned is that better detections come from understanding the data, not just writing more rules.

That is the part I wanted to get much better at.
