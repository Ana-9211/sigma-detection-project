# T1053.005 — Scheduled Task Creation

This one was pretty easy to understand once I looked at the actual execution flow. Scheduled tasks are a normal Windows feature, but attackers abuse them for persistence and delayed execution. The rule is about catching the creation of the task itself, not just the payload that eventually runs later.

## Technique

Scheduled tasks are a classic persistence mechanism. An attacker can configure a task to run at a specific time or trigger, which lets them execute code without needing to keep the process running continuously.

## Detection Logic

The rule focuses on the Windows task-creation utility and the command-line arguments used to create or schedule the task. The point is to catch the moment someone configures the system to execute something automatically.

I was not trying to flag every scheduled task on a system, because that would be a terrible signal. I was trying to isolate the creation pattern that looks like malicious persistence or task-based execution.

## Validation

The rule matched the expected scheduled-task activity in the sample set. That made sense because scheduled tasks are such a common persistence method in attack scenarios. The detections were not random; they were aligned with the planned execution chain.

One thing I learned here is that a task creation event is not automatically malicious. It becomes suspicious when the command line, target executable, and execution context match attacker behavior.

## False Positive Considerations

This rule definitely has some normal admin noise. Patch management, software updates, and enterprise automation tools all create scheduled tasks. So I would not treat a match as proof of compromise on its own. I would want the surrounding context.

## Portability

The rule converted to Splunk without much trouble, and it kept the same logic. It was one of the more straightforward rules in the project, but it still reinforced an important lesson: persistence is often just a legit Windows feature being abused in a very normal-looking way.
