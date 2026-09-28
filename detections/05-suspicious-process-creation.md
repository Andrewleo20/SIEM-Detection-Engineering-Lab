# Detection 05 — Suspicious Process Creation

## Objective

Detect suspicious process relationships where PowerShell launches the Windows Command Shell (`cmd.exe`).

Process ancestry is valuable during SOC investigations because unusual parent-child relationships can indicate scripted execution or suspicious command chaining.

## Data Source

- Sysmon
- Event ID: `1` — Process Creation
- SIEM: Splunk Enterprise
- Log Source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`

## Detection Logic

The detection analyzes Sysmon Event ID 1 process-creation telemetry and identifies instances where `powershell.exe` is the parent process and `cmd.exe` is the child process.

## SPL Query

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<process>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]ParentImage['\"]>(?<parent_process>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]CommandLine['\"]>(?<command_line>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]User['\"]>(?<user>[^<]*)</Data>"
| search event_id=1 process="*\\cmd.exe" parent_process="*\\powershell.exe"
| table _time user parent_process process command_line
| sort - _time
```

## Alert Configuration

- **Alert Name:** Suspicious PowerShell Spawned Command Shell
- **Type:** Scheduled
- **Schedule:** Every 1 minute
- **Search Window:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Severity:** Medium

## Lab Validation

A controlled test was performed on the Windows SOC VM in which PowerShell launched `cmd.exe`.

Sysmon recorded the child process, parent process, command line, user, and timestamp as Event ID 1. The telemetry was forwarded to Splunk and successfully matched the detection.

## SOC Investigation

An analyst investigating the alert should examine:

- Parent and child process relationship
- Full command line
- User responsible for execution
- Processes created before and after the event
- Related PowerShell activity
- Network connections associated with either process
- Other endpoint alerts around the same timestamp

## Potential False Positives

PowerShell can legitimately launch `cmd.exe` during:

- Administrative scripts
- Software installation
- Troubleshooting
- Automation workflows
- IT management activity

The process relationship therefore provides an investigation signal rather than proof of malicious activity.

## MITRE ATT&CK Note

No specific ATT&CK technique is assigned solely from this parent-child process relationship. Additional behavioral context would be required for a more precise mapping.
