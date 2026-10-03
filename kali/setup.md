# Kali Linux Workstation

## Purpose

The Kali Linux virtual machine provides a dedicated security testing and network analysis environment within the home lab.

Its current role is to provide an isolated workstation for security tooling and to support future controlled testing against other systems within the lab.

## Virtual Machine Configuration

| Component | Configuration |
|---|---|
| Operating System | Kali Linux |
| Memory | 6 GB |
| CPU | 1 processor / 4 cores |
| Network | VMware NAT |
| Hypervisor | VMware Workstation Pro |

The virtual machine was deployed using the official Kali VMware image and a clean baseline snapshot was created after initial configuration.

## Current Role

At this stage of the project, Kali forms part of the lab infrastructure but has not yet been used extensively in the SIEM detection exercises documented in this repository.

The initial detection testing was performed directly on WIN11-DFIR to validate the complete telemetry and alerting pipeline before introducing additional systems and simulated activity.

Future exercises will use Kali to support controlled security testing, network analysis and the generation of additional telemetry for detection-engineering scenarios.
