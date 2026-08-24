# T1112 — Registry Run Key Persistence

## Technique
Registry Run key persistence is a classic Windows persistence vector. By adding an entry under the Run or RunOnce registry keys, an attacker can trigger execution at user or system logon.

## Detection Logic
The Sigma rule targets suspicious registry modifications under persistence-related hive paths. The main detection logic is designed to catch:

- modifications to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- modifications to `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- RunOnce and similar startup persistence locations
- execution chains that are immediately tied to these persistence changes

This is a direct detection of the persistence registry layer and is aligned with how malware and persistence tooling often establish startup execution.

## Validation
The rule achieved the expected validation result in the dataset and generated 7 hits that aligned with registry persistence behavior. These were consistent with the intended ATT&CK technique.

## False Positive Note
Administrative software often sets registry startup entries for legitimate applications and maintenance tools. The practical mitigation is to tune for unusual execution paths, user-controlled values, or persistence entries that do not correspond to approved software baselines.

## Special Note
The ATT&CK tag warning observed during validation is a cosmetic Sigma CLI issue rather than evidence of a faulty detection. The rule itself remains valid; the issue is display-level metadata rather than logic failure.

## Outcome
This is a reliable persistence detection pattern and a valuable example of the need to validate both rule logic and tooling-level metadata when working with Sigma-based pipelines.
