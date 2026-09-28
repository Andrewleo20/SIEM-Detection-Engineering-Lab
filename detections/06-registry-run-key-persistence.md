# Detection 06 — Registry Run-Key Persistence

## Objective

Detect modifications to Windows Registry Run and RunOnce keys. These registry locations can be used to automatically execute programs when a user logs on, making them relevant locations for persistence monitoring.

## Data Source

- Sysmon
- Event ID: `13` — Registry Value Set
- SIEM: Splunk Enterprise
- Log Source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`

## Detection Logic

The detection analyzes Sysmon Event ID 13 telemetry and identifies registry value modifications involving Windows `CurrentVersion\Run` or `CurrentVersion\RunOnce` paths.

## SPL Query

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]EventType['\"]>(?<event_type>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]TargetObject['\"]>(?<target_object>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]Details['\"]>(?<details>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<process>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]User['\"]>(?<user>[^<]*)</Data>"
| search event_id=13
| where like(lower(target_object), "%\\currentversion\\run\\%") OR like(lower(target_object), "%\\currentversion\\runonce\\%")
| table _time user process target_object details
| sort - _time
```

## Alert Configuration

- **Alert Name:** Registry Run-Key Persistence
- **Type:** Scheduled
- **Schedule:** Every 1 minute
- **Search Window:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Severity:** Medium

## MITRE ATT&CK

- **Technique:** Registry Run Keys / Startup Folder
- **Technique ID:** T1547.001

## Lab Validation

A controlled registry value was created within a Windows Run key on the SOC VM to simulate persistence-related registry activity.

Sysmon captured the registry modification as Event ID 13. The event was forwarded to Splunk and successfully identified by the SPL detection.

The temporary test registry value was removed after validation.

## SOC Investigation

An analyst investigating this detection should review:

- Registry path and modified value
- Process responsible for the modification
- User associated with the activity
- Executable or command configured in the registry value
- Process creation events around the same timestamp
- Whether the referenced executable is expected and trusted
- Other persistence-related activity on the endpoint

## Potential False Positives

Run and RunOnce keys are also commonly modified by legitimate software, including:

- Software installers and updaters
- Web browsers
- Endpoint management applications
- User applications configured to launch at logon

For example, normal applications may generate Run-key telemetry in the dashboard. The process, registry value, executable path, and surrounding activity should therefore be reviewed before escalation.

## Detection Tuning

In a production environment, known legitimate applications that frequently modify these registry locations could be baselined or allowlisted after validation.

Tuning should be performed carefully so that unusual Run-key modifications remain visible.
