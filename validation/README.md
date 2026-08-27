# Validation Evidence

The detection snapshots in the repository root are generated from the public
EVTX ATT&CK sample set using the local Zircolite checkout. The raw EVTX files
and Zircolite source remain local-only because they are large external inputs;
they are excluded by `.gitignore`.

Each snapshot is JSON output from a local detection run. The corresponding
writeup identifies the sample and summarizes the observed result. These files
are evidence of the recorded run, not a substitute for rerunning the corpus.

## Reproduce the syntax check

```text
python -m pip install sigma-cli
sigma check rules
```

The same check runs in GitHub Actions for every push and pull request. Raw-data
validation remains a local workflow because the sample corpus is not vendored.