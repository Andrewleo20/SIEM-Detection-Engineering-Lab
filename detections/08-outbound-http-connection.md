# Detection 08 — Suspicious Outbound HTTP Connection

## Objective

Identify outbound HTTP connections from the monitored Windows endpoint to external IP addresses using Sysmon network telemetry.

The detection provides network activity for SOC investigation; an external HTTP connection alone does not prove command-and-control or data exfiltration.

## Data Source

- Sysmon
- Event ID: `3` — Network Connection
- SIEM: Splunk Enterprise
- Log Source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`

## Detection Logic

The detection identifies Sysmon Event ID 3 connections using destination port 80 and removes loopback and lab/private destination ranges from the results.

## SPL Query

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID[^>]*>(?<event_id>\d+)</EventID>"
| rex field=_raw "<Data Name=['\"]Image['\"]>(?<process>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]DestinationIp['\"]>(?<destination_ip>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]DestinationPort['\"]>(?<destination_port>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]Protocol['\"]>(?<protocol>[^<]*)</Data>"
| rex field=_raw "<Data Name=['\"]User['\"]>(?<user>[^<]*)</Data>"
| search event_id=3 destination_port=80
| where destination_ip!="127.0.0.1" AND NOT like(destination_ip,"192.168.%") AND NOT like(destination_ip,"10.%")
| table _time user process destination_ip destination_port protocol
| sort - _time
```

## Alert Configuration

- **Alert Name:** Suspicious Outbound HTTP Connection
- **Type:** Scheduled
- **Schedule:** Every 1 minute
- **Search Window:** Last 5 minutes
- **Trigger Condition:** Number of results > 0
- **Severity:** Medium

## Lab Validation

A controlled outbound HTTP request was generated from the Windows SOC VM.

Sysmon Event ID 3 captured the connection and the Splunk Universal Forwarder delivered the telemetry to the Splunk server.

The test produced an external connection to:

- **Destination IP:** `172.66.147.243`
- **Destination Port:** `80`
- **Protocol:** TCP

The associated process appeared as `<unknown process>` in the captured network telemetry, so the detection does not claim a specific originating process.

## SOC Investigation

An analyst should examine:

- Destination IP address
- Destination port and protocol
- Initiating process when available
- User context
- Destination reputation
- Related DNS activity
- Process creation around the connection time
- Repeated or unusual outbound communication

## Potential False Positives

Normal applications can make outbound HTTP connections, including:

- Browsers
- Software updaters
- Operating-system services
- Administrative utilities
- Enterprise applications

External HTTP activity should therefore be correlated with endpoint and network context before escalation.

## MITRE ATT&CK Note

No specific ATT&CK technique is assigned solely from an outbound HTTP connection. Additional evidence would be required to classify the activity as command-and-control, exfiltration, or another ATT&CK behavior.

## Lab Troubleshooting Note

During implementation, the original Sysmon configuration suppressed new Event ID 3 telemetry. A minimal NetworkConnect configuration was used to isolate the issue and verify the complete pipeline:

`Windows Endpoint → Sysmon → Splunk Universal Forwarder → Splunk Enterprise`

This troubleshooting confirmed that network telemetry ingestion was functioning correctly once Event ID 3 generation was enabled.
