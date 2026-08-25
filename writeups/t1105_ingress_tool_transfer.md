# T1105 — Ingress Tool Transfer via LOLBAS Downloaders

This was a good example of a LOLOBAS-style detection. The idea is that an attacker does not need to run an obviously malicious downloader. They can use trusted Windows utilities to fetch a second-stage payload or tool.

## Technique

Ingress Tool Transfer is basically the movement of extra tooling into a compromised environment. Attackers often use utilities like `certutil.exe` or `bitsadmin.exe` because they are already present on Windows and can be used for downloads without dropping a new suspicious executable.

## Detection Logic

The rule watches for `certutil.exe` and `bitsadmin.exe` being used with download-like indicators such as `urlcache`, `-split`, `/transfer`, or `http`. That combination matters because a plain utility execution on its own is not suspicious enough.

The detection is specifically looking for download behavior, which makes it much more useful than just matching the binary name.

## Validation

It matched 4 events in the sample set, which felt reasonable. A lot of the other downloads in the dataset were done via PowerShell instead, so this rule was only covering the certutil and bitsadmin path, not every possible downloader method.

That was a useful learning moment: coverage is not “all possible downloads.” It is “this specific execution style that uses these binaries and arguments.”

## False Positive Considerations

`certutil.exe` is legitimate for certificate workflows, so I would not treat a hit as automatic malicious behavior. I would check the full command line, remote URL, destination path, the user context, and whether that process tree looked normal.

## Portability

The Splunk conversion worked well and kept the same logic. It is one of those detections that is useful to query across multiple backends because download behavior matters in both endpoint and SIEM work.
