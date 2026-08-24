# T1053.005 — Scheduled Task Creation

## Technique
Scheduled Task Creation is a common persistence and execution mechanism on Windows. Attackers frequently use `schtasks.exe`, `at.exe`, or task XML payloads to establish recurring execution and maintain footholds.

## Detection Logic
The Sigma rule focuses on the execution of task creation tooling and task-first operational patterns. The primary indicators are:

- process execution of `schtasks.exe`
- creation or modification of scheduled tasks
- command-line patterns consistent with persistence, silent execution, or remote scheduling

This is the classic detection pattern for persistence through task scheduling because it identifies the orchestration layer rather than just the eventual payload execution.

## Validation
The validation set produced 7 hits aligned with the expected technique. The rule reached the intended task-creation behavior and captured the relevant operational pattern with a clean signal.

## False Positive Note
The main false positive risk is legitimate administrative use of scheduled tasks in software maintenance, patching, or operational automation. This is manageable when the rule is scoped around suspicious command patterns, hidden tasks, or execution of high-risk child processes.

## Outcome
This is a solid detection that maps well to attacker behavior in the test corpus and reflects a standard Windows persistence pattern that defenders should monitor closely.
