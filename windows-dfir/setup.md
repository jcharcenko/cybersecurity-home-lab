# Windows 11 DFIR Workstation

## Purpose

The WIN11-DFIR virtual machine serves two roles within the home lab:

1. A monitored Windows endpoint that generates security telemetry for analysis in Splunk.
2. A dedicated digital forensics workstation containing tools for endpoint, memory, artefact and network analysis.

The workstation was built as a Windows 11 Pro virtual machine in VMware Workstation Pro and configured with Sysmon and the Splunk Universal Forwarder to provide endpoint telemetry to the central Splunk server.

## Virtual Machine Configuration

| Component | Configuration |
|---|---|
| Operating System | Windows 11 Pro |
| VM Name | WIN11-DFIR |
| Memory | 8 GB |
| CPU | 1 processor / 4 cores |
| Storage | 100 GB dynamically allocated |
| Network | VMware NAT |
| SIEM Forwarding | Splunk Universal Forwarder |
| Splunk Destination | Ubuntu-Splunk over TCP 9997 |

## DFIR Toolset

The workstation currently contains the following tools:

- **Sysinternals Suite** - Windows system and process analysis
- **Eric Zimmerman Tools** - Windows forensic artefact analysis
- **KAPE** - forensic collection and processing
- **Autopsy** - disk and file-system forensic analysis
- **Volatility 3** - memory forensics
- **Wireshark** - network packet capture and analysis
- **Sysmon** - enhanced Windows endpoint telemetry
- **Splunk Universal Forwarder** - forwarding endpoint telemetry to the SIEM

## Sysmon Configuration

Sysmon was installed to provide enhanced Windows endpoint telemetry, including process creation events used by the Splunk detection rules.

The Sysmon executable and configuration are stored under:

`C:\DFIR\Sysmon\`

The SwiftOnSecurity Sysmon configuration was used as the initial configuration baseline:

```powershell
.\Sysmon64.exe -i .\sysmonconfig-export.xml
```

After installation, the `Sysmon64` service was verified as running and events were confirmed in:

`Microsoft-Windows-Sysmon/Operational`

Sysmon Event ID 1 (Process Create) is currently used by the lab to monitor PowerShell execution and command-line activity.

## Splunk Universal Forwarder

The Splunk Universal Forwarder is installed on WIN11-DFIR and sends endpoint telemetry to the Ubuntu-Splunk server at:

`192.168.134.10:9997`

The current `inputs.conf` enables collection of both Sysmon and Windows Security events:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true

[WinEventLog://Security]
disabled = 0
renderXml = true
```

The forwarder runs using the Windows virtual service account:

`NT SERVICE\SplunkForwarder`

### Event Log Permission Issue

During initial configuration, the Universal Forwarder was unable to read the Sysmon Operational event log.

The issue was resolved by adding the Splunk Forwarder service account to the local **Event Log Readers** group:

```powershell
Add-LocalGroupMember -Group "Event Log Readers" -Member "NT SERVICE\SplunkForwarder"
```

Membership was verified with:

```powershell
Get-LocalGroupMember -Group "Event Log Readers"
```

After restarting the Splunk Forwarder service, Sysmon events were successfully received by Splunk Enterprise.

This troubleshooting step demonstrated that successful network connectivity to the Splunk server does not by itself guarantee telemetry collection. The forwarding service must also have sufficient permissions to access the underlying Windows event source.

## Telemetry Validation

Connectivity from WIN11-DFIR to the Splunk server was verified using PowerShell:

```powershell
Test-NetConnection 192.168.134.10 -Port 9997
```

A successful result confirmed that the Windows endpoint could reach the Splunk receiving port.

Sysmon telemetry was then verified in Splunk using:

```spl
index=main host="WIN11-DFIR"
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

Windows Security telemetry was verified using:

```spl
index=main host="WIN11-DFIR"
sourcetype="XmlWinEventLog:Security"
```

This confirmed the complete telemetry path:

**Windows Event Source → Splunk Universal Forwarder → TCP 9997 → Splunk Enterprise**

Both data sources are now used by the SIEM detection rules documented elsewhere in this project.
