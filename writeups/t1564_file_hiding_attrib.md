# T1564.001 — File Hiding via attrib.exe

This one was one of the cleaner detections in the project. It is simple but effective because the attacker is literally using the Windows file attribute utility to hide files or directories from normal view.

## Technique

File hiding is a classic defense evasion technique. If an attacker marks files or folders as hidden or system files, they become much harder to spot during regular user browsing or quick investigation.

## Detection Logic

The rule looks for `attrib.exe` being used with arguments that hide or change file attributes. It is a very direct signal because the command itself is the behavior being abused.

This was nice because it was a narrow rule with a clear purpose. There was no need to overcomplicate it. The suspicious activity is the file-hiding action itself.

## Validation

It matched exactly once in the dataset, which was a strong result. The rule hit the expected sample and the signal was precise instead of broad. That made it feel like a solid detection rather than a noisy general-purpose alert.

This also reinforced something I noticed earlier: sometimes the best rule is not the most complicated one. A small, specific detection can be much more useful than a noisy one with lots of hits.

## False Positive Considerations

There is some risk of false positives because admins and maintenance tools can use `attrib.exe` for legitimate work. But the pattern is specific enough that the noise risk is much lower than it is for things like PowerShell, WMI, or broad process-creation matching.

## Portability

The rule converted cleanly into Splunk without much extra work. It was a good example of a detection that is simple, precise, and still useful in a real environment.
