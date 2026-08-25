# T1105 — Tool Transfer via certutil and bitsadmin

This one is a good example of a LOLOBAS detection. The idea is that an attacker does not need to run an obviously malicious downloader. They can use trusted Windows utilities to fetch second-stage tooling.

## What I was checking

The rule watches for certutil.exe and bitsadmin.exe being used with download-like arguments. The important part is the combination of the binary and the command line. A plain certutil execution is not enough. It has to look like file download activity.

That is why the rule includes things like urlcache, -split, /transfer, and http. Those indicators separate the suspicious use from normal certificate or admin operations.

## Validation

It matched 4 events in the sample set, which felt reasonable. A lot of the other downloads in the dataset were done through PowerShell instead, so this rule was catching only the certutil or bitsadmin path rather than every possible download method.

That made me realise I had to stop thinking of detection coverage as a total count of all download behavior. It is just coverage for one specific execution style.

## False positives

certutil is legitimate for certificate workflows, so this is not an automatic malicious alert. In a real environment, I would always check the command line, remote URL, destination path, and the user that launched it.

## Portability

The Splunk conversion worked fine. It preserved the same logic, which is useful because download activity is one of those things defenders want to be able to query in multiple backends.
