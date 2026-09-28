# Detection 03 — Suspicious PowerShell Execution

## Objective

Detect suspicious PowerShell execution using command-line patterns commonly associated with bypassing PowerShell execution restrictions.

This detection focuses on PowerShell processes launched with the `ExecutionPolicy Bypass` option.

## Data Source

- Sysmon
- Event ID: `1` — Process Creation
- SIEM: Splunk Enterprise
- Log Source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`

## Detection Logic

Sysmon Event ID 1 records process creation activity, including the executable path, command line, and user context.

The detection identifies `powershell.exe` processes whose command line contains `ExecutionPolicy Bypass`.

## SPL Query

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<process>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]CommandLine['\"]>(?<command_line>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]User['\"]>(?<user>[^<]*)</Data>"
| search event_id=1 process="*powershell.exe"
| where like(lower(command_line), "%executionpolicy%bypass%")
| table _time user process command_line
| sort - _time
```

## Alert Configuration

- **Alert Name:** Suspicious PowerShell Execution
- **Type:** Scheduled
- **Schedule:** Every 1 minute
- **Search Window:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Severity:** Medium

## MITRE ATT&CK

- **Technique:** PowerShell
- **Technique ID:** T1059.001

## Lab Validation

A controlled PowerShell command using the `ExecutionPolicy Bypass` option was executed on the Windows SOC VM.

Sysmon captured the process creation as Event ID 1, including the PowerShell executable and command-line arguments. The event was forwarded to Splunk and successfully matched the detection logic.

## SOC Investigation

An analyst investigating this alert should examine:

- User executing PowerShell
- Full PowerShell command line
- Parent process
- Execution time
- Additional processes spawned by PowerShell
- Network activity associated with the process
- Related endpoint events occurring before and after execution

The command itself should be reviewed before determining whether the activity is malicious.

## Potential False Positives

PowerShell with execution-policy bypass options can also be used legitimately by:

- System administrators
- Deployment scripts
- Software installers
- IT automation tools
- Troubleshooting procedures

The detection therefore provides suspicious execution telemetry for investigation rather than proving malicious activity by itself.
