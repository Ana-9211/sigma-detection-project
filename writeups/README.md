# Detection Engineering Notes

This folder is basically my learning log for the Sigma work in this project. It is not a polished final report. It is more like the notes I wrote while figuring out how each rule actually behaved when I tested it against real attack samples.

## Included writeups

- [T1003.001 — LSASS Credential Dumping](./t1003_lsass_memory_access.md)
- [T1021.001 — Interactive Logon via RDP](./t1021_rdp_logon.md)
- [T1047 — WMI Execution via WmiPrvSE parentage](./t1047_wmi_execution_parentage.md)
- [T1053.005 — Scheduled Task Creation](./t1053_scheduled_task_creation.md)
- [T1055 — Process Injection via CreateRemoteThread](./t1055_createremotethread_injection.md)
- [T1059.001 — Suspicious PowerShell Execution](./t1059_suspicious_powershell_execution.md)
- [T1070.001 — Clear Windows Event Logs](./t1070_security_log_cleared.md)
- [T1087 and T1069 — Account and Group Discovery](./t1087_t1069_account_group_discovery.md)
- [T1090.001 — Internal Proxy via netsh portproxy](./t1090_netsh_portproxy.md)
- [T1105 — Ingress Tool Transfer](./t1105_ingress_tool_transfer.md)
- [T1112 — Registry Run Key Persistence](./t1112_registry_run_key_persistence.md)
- [T1218.005 — Mshta Signed Binary Proxy Execution](./t1218_mshta_lolbas.md)
- [T1218.011 — Rundll32 Signed Binary Proxy Execution](./t1218_rundll32_lolbas.md)
- [T1548.002 — UAC Bypass via Auto-Elevate Parentage](./t1548_uac_bypass_parentage.md)
- [T1564.001 — File Hiding via attrib.exe](./t1564_file_hiding_attrib.md)

## Why these matter

These writeups are useful because they show the real process I went through. I did not just write rules and move on. I tested them, saw where the data disagreed with my assumptions, fixed the logic, and then wrote down why the fix mattered.

That is the part that felt like actual learning.
