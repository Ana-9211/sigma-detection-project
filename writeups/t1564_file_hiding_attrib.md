# T1564.001 — File Hiding via attrib.exe

This was one of the cleanest detections in the whole project. It is simple but effective because the attacker is literally using the Windows file attribute utility to hide files or folders.

## What the rule is catching

The rule watches for attrib.exe with arguments that set hidden or system attributes. That is the tell that someone is trying to hide files from normal view.

It is a very direct technique, and the dataset had a clear sample for it. That made it easy to validate and easy to reason about.

## Validation

The rule matched exactly once, which was a strong result. It was one of those situations where the detection lined up cleanly with the actual telemetry, and it was satisfying because the signal was precise rather than broad.

This also made me realize that some of the best detections are not the complicated ones. Sometimes a small, narrow rule that matches a clear attacker action is more valuable than a noisy rule with a lot of hits.

## False positives

There is still a small chance of false positives because admins and maintenance tools can also use attrib.exe. But the risk is much lower here than with something like PowerShell or WMI because the pattern is very specific.

## Overall takeaway

This was a good reminder that precise rules can be really valuable. A simple detection that cleanly matches the attacker behavior is often better than a complicated one that tries to catch too many things at once.
