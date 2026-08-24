# Sigma Detection Engineering Portfolio

This repository is a focused detection-engineering portfolio built around Sigma rules, telemetry validation, and attacker-technique coverage against Windows event data.

## Scope

- Sigma rule authoring for Windows ATT&CK techniques
- Query conversion for Splunk/Sigma workflow
- Validation using representative EVTX samples and Zircolite
- Detection-gap analysis and troubleshooting for log-source coverage
- Documentation of the reasoning and trade-offs behind each rule

## Contents

- `rules/` — Sigma YAML rules for detections developed in this project
- `converted-queries/` — Splunk-style converted queries for validation and comparison
- `writeups/` — narrative writeups covering detection logic, validation, false positives, and telemetry findings

## Notes on tooling and data

This project intentionally keeps the source artifacts that were authored here and avoids vendoring third-party tool chains or large public sample sets into the repository itself.

- Zircolite is used as the validation engine, but the project references the upstream project rather than storing the full vendor tree here.
- The EVTX ATT&CK sample set is also external to this repo and is treated as a referenced test corpus rather than a bundled dataset.

## Key detection themes

This project focused on Windows ATT&CK techniques with real validation against telemetry where the evidence source mattered as much as the rule logic itself. A major outcome was identifying when a technique was present in the data but captured under a different log source than the initial rule assumed.

## Portfolio value

The strongest part of this project is not just the rules themselves, but the evidence trail showing how detection logic was tested, challenged, and corrected when the data did not match expectations.
