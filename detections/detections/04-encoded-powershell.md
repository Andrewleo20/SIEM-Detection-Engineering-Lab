# Detection 04 — Encoded PowerShell Execution

## Objective

Detect PowerShell processes executed with encoded command-line arguments. Encoded PowerShell commands can be used to obscure script contents and make command-line activity more difficult to inspect.

## Data Source

- Sysmon
- Event ID: `1` — Process Creation
- SIEM: Splunk Enterprise
- Log Source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`

## Detection Logic

The detection analyzes Sysmon process-creation events for `powershell.exe` and searches the command line for PowerShell encoded-command parameters such as `EncodedCommand` or `-enc`.

## SPL Query

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<process>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]CommandLine['\"]>(?<command_line>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]User['\"]>(?<user>[^<]*)</Data>"
| search event_id=1 process="*powershell.exe"
| where like(lower(command_line), "%encodedcommand%") OR like(lower(command_line), "% -enc %")
| table _time user process command_line
| sort - _time
```

## Alert Configuration

- **Alert Name:** Encoded PowerShell Execution
- **Type:** Scheduled
- **Schedule:** Every 1 minute
- **Search Window:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Severity:** Medium

## MITRE ATT&CK

- **Technique:** PowerShell
- **Technique ID:** T1059.001

## Lab Validation

A controlled encoded PowerShell command was executed on the Windows SOC VM.

Sysmon captured the PowerShell process as Event ID 1 and recorded its command-line arguments. The telemetry was forwarded by the Splunk Universal Forwarder and successfully identified by the SPL detection.

## SOC Investigation

An analyst investigating this alert should examine:

- Full PowerShell command line
- Encoded command contents
- User executing the process
- Parent process
- Processes subsequently created by PowerShell
- Related network connections
- Other endpoint activity around the execution time

Encoded content should be decoded and analyzed before determining the intent of the execution.

## Potential False Positives

Encoded PowerShell is not automatically malicious. Legitimate uses can include:

- Administrative automation
- Software deployment
- Management tools
- Enterprise scripts

Additional process, user, network, and endpoint context should therefore be correlated before escalating the activity.
