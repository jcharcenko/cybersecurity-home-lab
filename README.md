# cybersecurity-home-lab

A practical home SOC and DFIR lab built with VMware, Windows 11, Kali Linux, Sysmon and Splunk Enterprise for security monitoring, detection and investigation.

## Overview

This project documents the design and implementation of my home cybersecurity lab, built to develop practical experience in security monitoring, detection engineering and digital forensics.

The environment combines Windows and Linux virtual machines with Splunk Enterprise to create a small SOC-style monitoring environment. Windows endpoint telemetry from Sysmon and Windows Security logs is collected through the Splunk Universal Forwarder and analysed centrally in Splunk.

Rather than focusing only on installation, the project documents the complete process of building and troubleshooting the environment, validating telemetry, creating detections and testing alerts through controlled activity.

## Lab Architecture

The lab runs in VMware Workstation Pro on a Windows 11 host and currently consists of three virtual machines:

- **Windows 11 DFIR Workstation** - monitored endpoint and digital forensics workstation running Sysmon, Splunk Universal Forwarder, Wireshark, KAPE, Autopsy, Volatility 3 and Eric Zimmerman tools.
- **Ubuntu Splunk Server** - Ubuntu Server running Splunk Enterprise as the central SIEM for log ingestion, searching, detection and alerting.
- **Kali Linux** - security testing and network analysis workstation for generating controlled activity and supporting future investigation exercises.

The virtual machines communicate through a VMware NAT network. Windows endpoint telemetry is forwarded to the Splunk server over TCP port 9997.

A visual architecture diagram is included below.

<!-- Architecture diagram will be added here -->

## SIEM Monitoring and Detection

The Windows 11 endpoint forwards both Sysmon and Windows Security event telemetry to Splunk Enterprise using the Splunk Universal Forwarder.

The current lab includes three tested scheduled detections:

| Detection | Data Source | Event / Logic | Severity |
|---|---|---|---|
| PowerShell Process Execution | Sysmon | Event ID 1 - `powershell.exe` process creation | Medium |
| Encoded PowerShell Command Execution | Sysmon | Event ID 1 with `-enc` or `-EncodedCommand` | High |
| Local User Account Created | Windows Security | Event ID 4720 | High |

Each detection was tested through controlled activity on the Windows endpoint and verified through Splunk's Triggered Alerts.

Testing also demonstrated how a single event can satisfy multiple detection rules. For example, an encoded PowerShell command triggered both the general PowerShell execution detection and the more specific encoded-command detection. This provided a practical example of alert overlap, detection specificity and the need for tuning in a monitoring environment.

## Troubleshooting and Lessons Learned

Building the lab involved several configuration and troubleshooting challenges that helped develop a better understanding of how the components interact.

### Windows Event Log Permissions

The Splunk Universal Forwarder initially could not access the Sysmon Operational event log. The forwarder runs under the `NT SERVICE\SplunkForwarder` virtual account, which required membership in the Windows **Event Log Readers** group.

After correcting the permissions and restarting the forwarder, Sysmon telemetry was successfully ingested by Splunk.

### Working with Raw XML Events

Sysmon and Windows Security events were initially ingested as XML without all of the fields required by the detection searches being automatically extracted.

SPL `rex` expressions were used to extract fields such as:

- Event ID
- Process image
- Command line
- User
- Target account
- Account creator

This made it possible to build readable detection searches while also providing practical experience working directly with raw Windows event data.

### Scheduled Alert Timing

The detections run every five minutes and search the previous five-minute window. During testing, an event generated outside the relevant search window did not trigger an alert even though the event had been successfully logged and indexed.

This demonstrated an important distinction between **telemetry collection, detection logic and alert execution**. An event being present in the SIEM does not necessarily mean a scheduled detection will evaluate it.

### Detection Overlap

The encoded PowerShell test triggered both the general PowerShell process detection and the more specific encoded-command detection.

This demonstrated how overlapping detection logic can generate multiple alerts from the same underlying activity and highlighted the importance of detection tuning and correlation as a monitoring environment grows.
