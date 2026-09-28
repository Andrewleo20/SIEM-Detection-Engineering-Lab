# Detection 01 — Multiple Failed Windows Logins

## Objective

Detect repeated failed Windows authentication attempts against the same user account. Multiple failures within a short period can indicate brute-force activity, password guessing, or repeated authentication failures requiring SOC investigation.

## Data Source

- Windows Security Event Log
- Event ID: `4625` — An account failed to log on
- SIEM: Splunk Enterprise
- Log Source: `WinEventLog:Security`

## Detection Logic

The detection extracts the target username, source IP address, and logon type from Windows Event ID 4625. Events are grouped by account and source, and an alert is generated when five or more failed authentication attempts are observed.

## SPL Query

```spl
index=main source="WinEventLog:Security" "4625"
| rex field=_raw "<EventID[^>]*>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]TargetUserName['\"]>(?<target_user>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]IpAddress['\"]>(?<source_ip>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]LogonType['\"]>(?<logon_type>[^<]*)</Data>"
| search event_id=4625
| stats count AS failed_logins earliest(_time) AS first_seen latest(_time) AS last_seen BY target_user source_ip logon_type
| where failed_logins >= 5
| convert ctime(first_seen) ctime(last_seen)
| table target_user source_ip logon_type failed_logins first_seen last_seen
```

## Alert Configuration

- **Alert Name:** Multiple Failed Windows Logins
- **Type:** Scheduled
- **Schedule:** Every 1 minute
- **Search Window:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Severity:** Medium

## MITRE ATT&CK

- **Technique:** Brute Force
- **Technique ID:** T1110

## Lab Validation

A disposable Windows account named `soc-test` was used to safely generate repeated failed authentication attempts. Windows generated Event ID 4625 events, which were forwarded to Splunk using the Splunk Universal Forwarder.

The detection successfully aggregated the failed logons and identified the account once the configured threshold was reached.

## SOC Investigation

An analyst reviewing this alert should examine:

- Targeted user account
- Number and frequency of failed logins
- Source IP address
- Logon type
- Authentication activity before and after the failures
- Whether a successful login occurred following repeated failures

## Potential False Positives

Repeated failures do not automatically indicate malicious activity. Possible benign causes include:

- User repeatedly entering an incorrect password
- Cached or outdated credentials
- Misconfigured services or applications
- Authentication issues following a password change

These factors should be considered before escalating the event as a security incident.
