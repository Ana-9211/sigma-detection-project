# T1218.011 — Rundll32 Signed Binary Proxy Execution

This one was a classic LOLBAS detection. `rundll32.exe` is a normal Windows binary, and that is exactly why it is useful to attackers. They can abuse it to execute code through DLLs and function names in a way that looks a lot like regular system behavior.

## Technique

This is a signed binary proxy execution technique. An attacker is not directly launching a suspicious executable; instead, they are abusing the trusted Microsoft binary to call an exported function or DLL path that runs the malicious code.

## Detection Logic

The rule is looking for `rundll32.exe` together with known abused patterns like `zipfldr`, `shdocvw`, `advpack`, `comsvcs`, or `MiniDump`. The important part is that the suspicious signal is not simply “rundll32 exists,” but rather “rundll32 is being used with a known malicious function or DLL pattern.”

That is a good example of rule tuning. The binary is common, but the command line and DLL/function combination are what make it interesting.

## Validation

The dataset produced 6 hits for this rule. That felt like a valid result because this technique has multiple variants and the dataset included several different ways of abusing the same trusted binary.

This one also reinforced a point I keep seeing in detection work: trusted binaries are not safe by default. The trust is in the binary, but the behavior determines whether it is suspicious.

## False Positive Considerations

There are legitimate Windows and shell-extension use cases for `rundll32.exe`, so I would not blindly trust a single hit. I would want to look at the full command line, the DLL path, the function being called, and the parent process before I called it malicious.

## Portability

This converted into Splunk without much trouble and kept the same logic. It is another example of a rule that has to be precise enough to avoid noise, but still broad enough to catch the common execution variants people actually abuse.
