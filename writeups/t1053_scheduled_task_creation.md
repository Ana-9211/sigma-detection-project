# T1053.005 — Scheduled Tasks

This was one of the easier ones to understand once I saw the actual process execution. Scheduled tasks are a standard Windows feature, but attackers abuse them for persistence and delayed execution. The rule is basically about catching the creation of the task itself, not just the payload that eventually runs.

## What I was looking for

The rule focuses on the task creation utility and the command-line behavior around it. The idea is to catch the moment when a system is being configured to run something automatically in the future.

I was not trying to detect every scheduled task on the host. That would be useless. I was trying to catch the patterns that look like persistence or execution staging rather than normal admin maintenance.

## Validation

The detection matched what I expected in the dataset. It gave me a clean signal that scheduled-task creation was happening in the attack samples, which makes sense because scheduled tasks are such a common persistence mechanism.

The important thing I learned with this one is that not all scheduled tasks are malicious, but the creation pattern is still a useful signal when paired with the command line and the executable being launched.

## False positives

The main false positive risk is system maintenance, patching, and enterprise automation. A lot of legitimate software creates scheduled tasks. So this rule is best used with context rather than as a stand-alone alert.

## Overall impression

This was a solid rule because it matched a clear attacker behavior and was easy to reason about. It also reinforced the idea that many Windows persistence techniques are not mysterious. They are just regular admin features being abused.
