# Splunk Enterprise SIEM Server

## Purpose

The Ubuntu-Splunk virtual machine provides the central SIEM platform for the home lab.

Its role is to receive endpoint telemetry from WIN11-DFIR, index the collected events, support security analysis and run scheduled detection searches that generate alerts from monitored activity.

## Virtual Machine Configuration

| Component | Configuration |
|---|---|
| Operating System | Ubuntu Server 26.04.1 LTS |
| Hostname | splunk-server |
| VM Name | Ubuntu-Splunk |
| Memory | 6 GB |
| CPU | 1 processor / 2 cores |
| Storage | 60 GB dynamically allocated |
| Network | VMware NAT |
| IP Address | 192.168.134.10 |
| Splunk Receiving Port | TCP 9997 |
| Splunk Web Port | TCP 8000 |

The server uses a static IP address so that monitored endpoints have a consistent destination for telemetry forwarding.

## Splunk Enterprise

Splunk Enterprise is installed under:

```bash
/opt/splunk
```

The Splunk service runs under the dedicated Linux account:

```text
splunk
```

Service status can be checked using:

```bash
sudo systemctl status Splunkd
```

Splunk was also configured to start automatically with the Ubuntu server.

The Splunk web interface is available within the lab network on TCP port `8000`.

## Receiving Endpoint Telemetry

Splunk Enterprise is configured to receive data from Splunk Universal Forwarders on:

```text
TCP 9997
```

WIN11-DFIR forwards two Windows event sources:

- `Microsoft-Windows-Sysmon/Operational`
- `Security`

The telemetry is currently stored in the Splunk `main` index.

Example Sysmon search:

```spl
index=main host="WIN11-DFIR"
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

Example Windows Security search:

```spl
index=main host="WIN11-DFIR"
sourcetype="XmlWinEventLog:Security"
```

## Current SIEM Workflow

The current monitoring pipeline is:

**Windows telemetry → Splunk Universal Forwarder → TCP 9997 → Splunk Enterprise → SPL detection search → Triggered Alert**

This provides the foundation for developing and testing security monitoring use cases within the lab.

The initial implementation currently includes scheduled detections for PowerShell process execution, encoded PowerShell commands and Windows local account creation. The detection logic and testing methodology are documented separately in `detections.md`.

## Validation

Connectivity to the Splunk receiving port was verified from WIN11-DFIR:

```powershell
Test-NetConnection 192.168.134.10 -Port 9997
```

The test returned:

```text
TcpTestSucceeded : True
```

Successful ingestion was then confirmed by searching for events from the Windows endpoint in Splunk.

Both Sysmon and Windows Security telemetry were observed from `WIN11-DFIR`, confirming that the forwarding and ingestion pipeline was operational.

This established a working baseline before detection rules and alerting were introduced.
