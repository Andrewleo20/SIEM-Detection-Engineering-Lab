# Detection 02 — Password Spraying

## Objective

Detect password-spraying behavior where authentication failures occur across multiple user accounts from the same source. Unlike traditional brute-force activity against one account, password spraying attempts a small number of passwords against many accounts.

## Data Source

- Windows Security Event Log
- Event ID: `4625` — An account failed to log on
- SIEM: Splunk Enterprise
- Log Source: `WinEventLog:Security`

## Detection Logic

The detection extracts the target username and source IP from Windows Event ID 4625. Failed authentication events are grouped by source IP, and the number of unique targeted accounts is calculated.

The detection triggers when the same source is associated with failed authentication attempts against five or more unique accounts.

## SPL Query

```spl
index=main source="WinEventLog:Security" "4625"
| rex field=_raw "<EventID[^>]*>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]TargetUserName['\"]>(?<target_user>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]IpAddress['\"]>(?<source_ip>[^<]*)</Data>"
| search event_id=4625
| stats dc(target_user) AS unique_accounts count AS failed_attempts values(target_user) AS targeted_accounts BY source_ip
| where unique_accounts >= 5
| table source_ip unique_accounts failed_attempts targeted_accounts
```

## Alert Configuration

- **Alert Name:** Password Spraying - Multiple Accounts
- **Type:** Scheduled
- **Schedule:** Every 1 minute
- **Search Window:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Severity:** Medium

## MITRE ATT&CK

- **Technique:** Brute Force: Password Spraying
- **Technique ID:** T1110.003

## Lab Validation

Five disposable Windows accounts (`spray-user1` through `spray-user5`) were used to safely simulate password-spraying behavior.

Failed authentication attempts were generated against the accounts using an incorrect password. Windows generated Event ID 4625 events, which were forwarded to Splunk.

The SPL detection successfully identified authentication failures distributed across multiple user accounts.

## SOC Investigation

An analyst investigating this detection should review:

- Source IP responsible for the authentication attempts
- Number of unique accounts targeted
- Total number of failed attempts
- Targeted usernames
- Timing and frequency of authentication failures
- Successful logons following the failed attempts
- Other security events associated with the source

## Potential False Positives

Possible benign causes include:

- Shared applications attempting authentication against multiple accounts
- Authentication infrastructure or configuration problems
- Automated administrative activity
- Outdated credentials used by enterprise services

The authentication pattern and surrounding activity should be investigated before classifying the event as malicious.
