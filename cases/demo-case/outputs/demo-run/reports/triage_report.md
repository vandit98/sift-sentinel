# SIFT Sentinel Triage Report: Demo Evil: Workstation Intrusion With Memory Injection

- Case ID: `demo-evil-001`
- Run ID: `demo-run`
- Generated UTC: `2026-04-30T21:04:29Z`
- Confirmed findings: `3`
- Inferred findings: `0`
- Refuted leads: `1`

## Executive Summary

SIFT Sentinel confirmed malicious execution, memory injection, external command-and-control, and Run key persistence after iterating through missing evidence checks.

## Confirmed Findings

### F-001: Winupdate.exe beacon with memory injection evidence

- Severity: `critical`
- Status: `confirmed`
- Confidence: `0.94`
- Hypothesis: A masqueraded winupdate.exe process communicated externally and contains injected executable memory.
- MITRE: `T1055, T1036, T1071`

Evidence:
- `memory_netstat` row 2 `remote_ip` = `45.77.89.22` via `memory_netstat-ec049d2484`
- `memory_processes` row 4 `image_path` = `C:\Users\Public\winupdate.exe` via `memory_processes-7254b57374`
- `disk_prefetch` row 1 `path` = `C:\Users\Public\winupdate.exe` via `disk_prefetch-b4e0f8c7f8`
- `memory_malfind` row 1 `protection` = `PAGE_EXECUTE_READWRITE` via `memory_malfind-4b813758f4`
- `disk_amcache` row 1 `sha1` = `6F1D7B81C0FF1DAA2D7C9CE9E6FAE7D2C2F40111` via `disk_amcache-9710726bbb`
- `disk_timeline` row 1 `event` = `FileCreate` via `disk_timeline-0e1e8f25f1`

Notes:
- `malfind`: Private VAD contains MZ header and shellcode-like strings; not backed by image file
- `pid`: 4884
- `remote_ip`: 45.77.89.22
- `remote_port`: 443
- `self_correction`: Confirmed after adding malfind, Amcache, and disk timeline evidence.
- `sha1`: 6F1D7B81C0FF1DAA2D7C9CE9E6FAE7D2C2F40111

### F-004: Encoded PowerShell staged winupdate.exe

- Severity: `high`
- Status: `confirmed`
- Confidence: `0.88`
- Hypothesis: PowerShell launched an encoded command that staged or executed winupdate.exe.
- MITRE: `T1059.001, T1105`

Evidence:
- `windows_events` row 1 `command_line` = `powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA7 Start-Process C:\Users\Public\winupdate.exe` via `windows_events-04d33d85db`
- `memory_processes` row 3 `command_line` = `powershell.exe -NoP -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA7 Start-Process C:\Users\Public\winupdate.exe` via `memory_processes-7254b57374`
- `disk_timeline` row 1 `path` = `C:\Users\Public\winupdate.exe` via `disk_timeline-0e1e8f25f1`

Notes:
- `self_correction`: Confirmed after process and timeline corroboration.
- `user`: ACME\jlee

### F-003: Run key persistence loads SyncCache.dll via rundll32

- Severity: `high`
- Status: `confirmed`
- Confidence: `0.91`
- Hypothesis: A user Run key persists a suspicious DLL through rundll32.exe.
- MITRE: `T1112, T1218.011, T1547.001`

Evidence:
- `windows_events` row 2 `command_line` = `rundll32.exe C:\ProgramData\AcmeCache\SyncCache.dll,Start` via `windows_events-04d33d85db`
- `disk_timeline` row 3 `path` = `C:\ProgramData\AcmeCache\SyncCache.dll` via `disk_timeline-0e1e8f25f1`
- `registry_run_keys` row 1 `value_data` = `rundll32.exe C:\ProgramData\AcmeCache\SyncCache.dll,Start` via `registry_run_keys-613612de4e`

Notes:
- `self_correction`: Confirmed only after registry Run key evidence was collected.


## Inferred Or Refuted Leads

### F-002: Uncorroborated svchost.exe path anomaly

- Severity: `medium`
- Status: `refuted`
- Confidence: `0.08`
- Hypothesis: Prefetch references svchost.exe outside System32, but this requires corroboration before reporting.
- MITRE: `T1036`

Evidence:
- `disk_prefetch` row 2 `path` = `C:\Users\Public\svchost.exe` via `disk_prefetch-b4e0f8c7f8`

Notes:
- `path`: C:\Users\Public\svchost.exe
- `self_correction`: Self-corrected: no Amcache or timeline record for the suspicious path, so this stays out of confirmed findings.


## Self-Correction And Validation

### VAL-001: External callback needs binary and memory corroboration

- Severity: `high`
- Finding: `F-001`
- Required action: `memory_malfind, disk_amcache, disk_timeline`
- Reason: Network evidence alone can misattribute a process; require injection, hash, and file timeline evidence.

### VAL-002: Svchost masquerade lead is single-source

- Severity: `medium`
- Finding: `F-002`
- Required action: `disk_amcache, disk_timeline`
- Reason: A Prefetch-only path anomaly is not enough for a confirmed report.

### VAL-003: Rundll32 execution needs persistence mechanism validation

- Severity: `high`
- Finding: `F-003`
- Required action: `registry_run_keys`
- Reason: Execution is not persistence until an ASEP or service mechanism is proven.


## Tool Execution Audit

- `case_manifest` `case_manifest-e29757092b`: ok; rows=0; started=2026-04-30T21:04:29Z; ended=2026-04-30T21:04:29Z
- `disk_amcache` `disk_amcache-9710726bbb`: ok; rows=3; started=2026-04-30T21:04:29Z; ended=2026-04-30T21:04:29Z
- `disk_prefetch` `disk_prefetch-b4e0f8c7f8`: ok; rows=3; started=2026-04-30T21:04:29Z; ended=2026-04-30T21:04:29Z
- `disk_timeline` `disk_timeline-0e1e8f25f1`: ok; rows=4; started=2026-04-30T21:04:29Z; ended=2026-04-30T21:04:29Z
- `memory_malfind` `memory_malfind-4b813758f4`: ok; rows=1; started=2026-04-30T21:04:29Z; ended=2026-04-30T21:04:29Z
- `memory_netstat` `memory_netstat-ec049d2484`: ok; rows=3; started=2026-04-30T21:04:29Z; ended=2026-04-30T21:04:29Z
- `memory_processes` `memory_processes-7254b57374`: ok; rows=5; started=2026-04-30T21:04:29Z; ended=2026-04-30T21:04:29Z
- `registry_run_keys` `registry_run_keys-613612de4e`: ok; rows=1; started=2026-04-30T21:04:29Z; ended=2026-04-30T21:04:29Z
- `windows_events` `windows_events-04d33d85db`: ok; rows=3; started=2026-04-30T21:04:29Z; ended=2026-04-30T21:04:29Z
