# T1564.001 — File Hiding via attrib.exe

## Technique
File hiding through `attrib.exe` is a defense evasion technique used to conceal files and folders by setting the hidden attribute. Attackers use this to make malicious artifacts less visible to an operator or user.

## Detection Logic
The rule focuses on executions of `attrib.exe` with arguments used to set the hidden or system attribute on files or directories. The indicator is straightforward:

- process name: `attrib.exe`
- command-line parameters that add `+h` and/or `+s`
- action against suspicious file or folder paths

This is a simple but effective detection because the attacker must invoke the underlying OS utility to alter file visibility.

## Validation
The validation produced an exact match at the expected detection rate: 1/1 exact match. This is a strong result and demonstrates that the rule logic cleanly lines up with the observed event pattern in the dataset.

## False Positive Note
The risk of false positives is low but not zero. System administrators and maintenance tooling sometimes use `attrib.exe` for legitimate file organization or repair tasks. Tuning by path context, parent process, or observed user context helps reduce noise.

## Outcome
This is a precise, low-noise detection that reflects a clear attacker technique and is easy to validate against the provided sample set.
