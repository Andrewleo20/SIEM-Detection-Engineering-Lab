# Detection 07 — Suspicious LSASS Process Access

## Objective

Detect processes accessing the Windows Local Security Authority Subsystem Service (`lsass.exe`). Access to LSASS is important security telemetry because credential-access activity may involve interaction with the LSASS process.

This lab simulated process access only; no credentials were dumped.

## Data Source

- Sysmon
- Event ID: `10` — Process Access
- SIEM: Splunk Enterprise
- Log Source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`

## Detection Logic

The detection analyzes Sysmon Event ID 10 and identifies processes whose target process is `lsass.exe`. It records the source process, target process, user context, and requested access rights.

## SPL Query

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]SourceImage['\"]>(?<source_process>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]TargetImage['\"]>(?<target_process>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]GrantedAccess['\"]>(?<granted_access>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]User['\"]>(?<user>[^<]*)</Data>"
| search event_id=10 target_process="*\\lsass.exe"
| table _time user source_process target_process granted_access
| sort - _time
```

## Alert Configuration

- **Alert Name:** Suspicious LSASS Process Access
- **Type:** Scheduled
- **Schedule:** Every 1 minute
- **Search Window:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Severity:** Medium

## MITRE ATT&CK

- **Technique:** OS Credential Dumping: LSASS Memory
- **Technique ID:** T1003.001

## Lab Validation

Sysmon was configured to monitor process access involving `C:\Windows\System32\lsass.exe`.

A controlled lab test generated LSASS process-access telemetry without performing credential dumping. Sysmon Event ID 10 was forwarded to Splunk and successfully detected.

## SOC Investigation

An analyst should review:

- Source process accessing LSASS
- Source process path and legitimacy
- Granted access rights
- User/security context
- Process ancestry
- Related process-creation events
- Other endpoint activity around the same timestamp

## Potential False Positives

Legitimate Windows and security software can access LSASS. The dashboard, for example, also demonstrated that normal system processes may generate LSASS-access telemetry.

Therefore, an Event ID 10 match alone does not prove credential dumping.

## Detection Tuning

Production detection should baseline expected LSASS access from trusted Windows and security processes and prioritize unusual source processes, paths, access rights, or behavioral context.
