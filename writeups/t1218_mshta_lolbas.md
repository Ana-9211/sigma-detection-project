# T1218.005 — Mshta Signed Binary Proxy Execution

This one was a good reminder that the executable name alone is not enough. `mshta.exe` is a normal Windows binary, which is exactly why attackers like it. It lets them run HTA content or script-based payloads while still looking like a trusted system process.

## Technique

This is a LOLBAS-style signed binary proxy execution technique. The attacker is not dropping a weird new executable; they are abusing a built-in Windows utility to run malicious script or remote content through a trusted path.

## Detection Logic

The rule is looking for `mshta.exe` together with suspicious indicators in the command line, like `javascript`, `vbscript`, `http`, or `.hta`. The focus is not on the binary itself, but on the behavior of running script content through HTA.

That difference matters a lot. If I looked for `mshta.exe` alone, I would get way too much noise. The command line is what gives the actual signal here.

## Validation

I tested it against the EVTX attack sample set and it matched 5 events. That felt realistic for this technique because the dataset had a few HTA/script execution patterns, but not every single one of them was using the same exact command-line shape.

This one also showed me that a lot of detection engineering is really about narrowing the rule until it matches the behavior you actually care about. The binary is common; the script/remote-content pattern is the suspicious part.

## False Positive Considerations

There are definitely legitimate HTA tools and installer scripts that could match this. So a hit should not be treated as automatic malicious activity by itself. I would want to check the script source, whether it was local or remote, and what the parent process and execution context looked like.

## Portability

The rule converted cleanly into Splunk using the Sysmon pipeline. This is one of those detections that makes sense in practice because it catches malicious execution hiding behind a trusted Windows utility instead of relying on a fake-looking binary name.
