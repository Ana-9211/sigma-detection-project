# T1090.001 — Internal Proxy via netsh portproxy

This one was a nice little pivot detection. It is basically port forwarding through a compromised machine so traffic can be relayed to another system or service. That is useful for lateral movement and keeping a malicious path hidden behind a host that already looks legitimate.

## Technique

The technique is internal proxying or port forwarding. An attacker can configure a local port on a compromised machine to forward traffic somewhere else, which gives them an easy way to move through a network or route traffic without exposing the original target directly.

## Detection Logic

The rule looks for `netsh.exe` commands with `portproxy` arguments. I was not flagging broad `netsh` use because that would be way too noisy. The signal is the actual portproxy configuration, which is a much narrower and more suspicious pattern.

This is one of those detections where the command line tells the whole story. If the action is specifically configuring port forwarding, then it is much more likely to be attacker activity than a normal network admin action.

## Validation

The dataset produced one exact match, which was a good sign. The sample file and the command line context lined up with the expected behavior, and the result was precise rather than broad.

It was a nice reminder that narrow detections can be valuable when they are built around the right indicator. A good rule does not need to be noisy to be useful.

## False Positive Considerations

Legitimate network engineering can configure port forwarding or similar relaying rules, especially in internal environments. So I would still want context before treating it as malicious. The key questions are whether that host normally does this and whether the command line matches a real admin process.

## Portability

This converted cleanly to Splunk and kept the same logic. It is a good example of a rule that is specific enough to stay useful without creating constant noise.
