# T1090.001 — Netsh Portproxy

This one felt like a neat little pivot detection. It is basically a way to set up port forwarding through a compromised machine so traffic can be relayed somewhere else. That is useful for lateral movement or C2 staging.

## What I was checking

The rule is looking for netsh.exe with portproxy-related arguments. I was not flagging any netsh usage in general because that would be too noisy. I was specifically looking for the portproxy configuration commands that indicate a forwarding rule is being set up.

That is a better signal because netsh is also a legitimate admin tool used for networking tasks.

## Validation

It matched exactly one event in the dataset, which was a good sign. The sample file name lined up with the expected activity, and the match was specific rather than broad. That made me trust the rule more because it was not just catching everything that touched netsh.exe.

It felt similar to the attrib rule in that the indicator was narrow and the result was precise. That is a nice pattern to see when a detection works well.

## False positives

Legit network engineering can absolutely use portproxy or similar forwarding rules. So I would still want context before treating it as malicious. The main thing is whether the host normally does this and whether the command line matches the expected admin pattern.

## Portability

The rule converted cleanly to Splunk and still preserved the same logic. It is a good example of a detection that is narrow enough to remain useful without being overly noisy.
