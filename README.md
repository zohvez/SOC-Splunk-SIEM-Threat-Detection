# 🛡️ SOC Attack Simulation & Detection Lab with Splunk

## 📌 Project Overview

This project documents a home-lab SOC workflow using **Kali Linux**,
**Windows 10**, **Splunk Enterprise**, **Splunk Universal Forwarder**,
and **Sysmon**. I simulated and investigated four security scenarios:

1. **Network reconnaissance**
2. **Brute-force attack**
3. **RDP remote-access / initial-access simulation**
4. **PowerShell execution**

The focus is on translating activity into endpoint and authentication
telemetry, writing Splunk Search Processing Language (SPL) queries,
identifying source IP addresses, and supporting SOC alert triage.
**Exploitation is intentionally excluded from this project.**

> All testing was performed in a controlled lab using systems configured
> for this purpose. Do not run these tests against systems without
> explicit authorization.

---

## 🧱 Lab Architecture

```text
┌─────────────────────────┐       ┌──────────────────────────┐
│ Kali Linux              │       │ Windows 10               │
│ Lab attacker / tester   │──────▶│ Host: MSEDGEWIN10        │
│ 192.168.93.128          │       │ 192.168.93.129           │
│                         │       │ 192.168.193.129          │
│ Nmap / test activity    │       │ Sysmon + Windows Logs    │
└─────────────────────────┘       │ Splunk Universal Forwarder│
                                  └────────────┬─────────────┘
                                               │ TCP 9997
                                               ▼
                                  ┌──────────────────────────┐
                                  │ Ubuntu Server            │
                                  │ Splunk Enterprise        │
                                  │ 192.168.93.135           │
                                  │ Index: main              │
                                  └──────────────────────────┘
```

**Lab note:** The Windows and Kali VMs have also used the
`192.168.193.0/24` lab network for RDP testing. Use the address that
matches the active virtual network in your environment.

---

## 🛠️ Tools & Technologies

| Tool / Technology | Purpose |
|---|---|
| **Splunk Enterprise** | Centralized log search and investigation |
| **Splunk Universal Forwarder** | Forwards Windows events to Splunk |
| **Sysmon** | Process-creation and network-connection telemetry |
| **Windows Security Event Log** | Authentication success and failure events |
| **Windows PowerShell Operational Log** | PowerShell script-block telemetry |
| **Kali Linux** | Authorized lab testing and reconnaissance |
| **Nmap** | Network and service discovery |
| **Hydra** | Controlled authentication-testing exercise |
| **SPL** | Searching, filtering, and correlating security events |
| **MITRE ATT&CK** | Mapping observed behaviors to techniques |

---

## ⚔️ Use Cases Practiced

| Use case | Primary telemetry | Detection / investigation goal |
|---|---|---|
| Reconnaissance | Sysmon Event ID **3**; Sysmon Event ID **1** where relevant | Investigate network connections and discovery-related process activity |
| Brute-force attack | Windows Security Event ID **4625** | Identify repeated authentication failures and source IP |
| Initial access / RDP simulation | Windows Security Event IDs **4624** and **4625** | Review successful and failed remote-interactive logons and source addresses |
| PowerShell execution | Sysmon Event ID **1**; PowerShell Operational Event ID **4104**, when available | Review process command lines and script-block activity |

---

## 1. 🔎 Network Reconnaissance

### Scenario

Nmap was used from Kali Linux to discover reachable services on the
authorized Windows lab endpoint. The results were compared with endpoint
network-connection telemetry forwarded to Splunk.

### Example reconnaissance command

```bash
nmap -Pn -sV -p 135,139,445,3389 192.168.193.129
```

Use the target IP that corresponds to the lab network currently enabled
in VMware. This command discovers service information; it does not
establish that a service is vulnerable.

### Relevant telemetry

- **Sysmon Event ID 3** --- Network connection, if enabled by the
    Sysmon configuration.
- **Sysmon Event ID 1** --- Process creation, useful when discovery
    commands are executed on the monitored Windows endpoint.
- A network scan may not create a process event on Windows because
    Nmap runs on Kali. The Windows endpoint may instead record the
    resulting connections.

### SPL query --- Network connections to common Windows services

```spl
index=main host="MSEDGEWIN10" EventCode=3
| where DestinationPort=135 OR DestinationPort=139 OR DestinationPort=445 OR DestinationPort=3389
| table _time Image SourceIp SourcePort DestinationIp DestinationPort Protocol
| sort - _time
```

### SPL query --- Review process activity related to discovery

```spl
index=main host="MSEDGEWIN10" EventCode=1
| search CommandLine="*whoami*" OR CommandLine="*net user*" OR CommandLine="*netstat*"
| table _time User Image ParentImage CommandLine
| sort - _time
```

### Investigation steps

1. Identify the destination services contacted during the test.
2. Check available source and destination address fields.
3. Compare the event timestamps with the Nmap scan window.
4. Treat open ports as exposed services---not as proof of a successful
    attack or vulnerability.

### MITRE ATT&CK mapping

- **T1046 --- Network Service Discovery** (Discovery)
- **T1049 --- System Network Connections Discovery** applies when the
    observed behavior is discovery of network connections on a system;
    do not map an Nmap port scan to T1049 solely because network
    telemetry exists.

---

## 2. 🔐 Brute-Force Attack Detection

### Scenario

A controlled SMB authentication-testing exercise was generated from Kali
Linux against the lab Windows endpoint. Windows Security logs were
forwarded to Splunk for investigation.

### Relevant telemetry

- **Event ID 4625** --- An account failed to log on.
- Source address and account fields can help identify the system and
    account involved.
- In the observed lab results, the Kali address `192.168.93.128`
    appeared as a source, with **63 matching failures** in the
    investigated results.

### SPL detection query

```spl
index=main host="MSEDGEWIN10" EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 10
| eval Alert="Potential Brute-Force Activity"
| eval MITRE="T1110 - Brute Force"
| table Account_Name Source_Network_Address count Alert MITRE
| sort - count
```

### Investigation steps

1. Identify accounts with repeated failures.
2. Review `Source_Network_Address` to determine where the attempts
    originated.
3. Correlate the time window with other authentication events.
4. Validate whether the activity is expected lab testing or requires
    escalation.

### MITRE ATT&CK mapping

- **T1110 --- Brute Force** (Credential Access)

---

## 3. 🖥️ Initial Access — RDP Remote-Access Simulation

### Scenario

Remote Desktop was enabled for a controlled lab test, and a remote
connection was initiated from Kali Linux to the Windows endpoint.
Windows Security events were searched in Splunk to distinguish
successful and failed remote-interactive logons.

This section documents remote-access telemetry and **does not claim that
a software vulnerability was exploited**.

### Relevant telemetry

- **Event ID 4624** --- Successful logon.
- **Event ID 4625** --- Failed logon.
- **Logon Type 10** --- RemoteInteractive, commonly associated with
    Remote Desktop sessions.
- The `Source_Network_Address` field may identify the connecting IP
    address when Windows records it.

### SPL query --- Successful RDP logons

```spl
index=main host="MSEDGEWIN10" EventCode=4624 LogonType=10
| table _time Account_Name Source_Network_Address Workstation_Name LogonType
| sort - _time
```

### SPL query --- Failed RDP logons

```spl
index=main host="MSEDGEWIN10" EventCode=4625 LogonType=10
| stats count by Account_Name Source_Network_Address
| sort - count
```

### Investigation steps

1. Confirm the logon type and result.
2. Identify the account and source address where present.
3. Compare successful logons with preceding failures from the same
    source.
4. Correlate the logon with process and network telemetry around the
    same timestamp.

### MITRE ATT&CK mapping

- **T1021.001 --- Remote Desktop Protocol** (Remote Services /
    commonly associated with Lateral Movement).
- **T1078 --- Valid Accounts** only where the evidence supports the
    use of valid credentials.

---

## 4. ⚡ PowerShell Execution Monitoring

### Scenario

Benign PowerShell commands were executed on the Windows endpoint to
validate collection and detection workflows. PowerShell Operational
logging and Sysmon process telemetry were used where available.

### Relevant telemetry

- **Sysmon Event ID 1** --- Process creation, including the image and
    command line when captured.
- **PowerShell Operational Event ID 4104** --- Script-block logging,
    when enabled.
- Search for suspicious-looking flags or script-related keywords as
    leads for investigation; a keyword match alone does not prove
    malicious behavior.

### SPL query --- PowerShell process creation

```spl
index=main host="MSEDGEWIN10" EventCode=1
| search Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
| table _time host User Image ParentImage ProcessId CommandLine
| sort - _time
```

### SPL query --- PowerShell script-block events

```spl
index=main host="MSEDGEWIN10" EventCode=4104
| table _time host User ScriptBlockText
| sort - _time
```

If your events use a different sourcetype or field names, inspect a raw
event and adjust the query to match the fields in your environment.

### Investigation steps

1. Review the process image, parent process, user, and command line.
2. Search script-block content for relevant activity and context.
3. Correlate the process with nearby network or authentication events.
4. Distinguish normal administrative commands from suspicious behavior
    before assigning severity.

### MITRE ATT&CK mapping

- **T1059.001 --- PowerShell** (Execution)

---

## 🔍 SOC Investigation Workflow

For each use case, I practiced the following workflow:

1. Generate controlled lab activity.
2. Confirm that Windows Security, PowerShell, and Sysmon events are
    collected.
3. Search and filter events in Splunk using SPL.
4. Identify relevant users, processes, source IPs, destinations, and
    timestamps.
5. Correlate related events and build an event timeline.
6. Map observed behavior to MITRE ATT&CK where supported by evidence.
7. Record findings and decide whether the activity is expected,
    suspicious, or requires escalation.

---

## 📊 Detection Coverage Summary

| Use case | Event / data source | Primary detection objective |
|---|---|---|
| Reconnaissance | Sysmon 3; Sysmon 1 where applicable | Connections to exposed services and discovery activity |
| Brute-force attack | Security 4625 | Repeated failures by account and source |
| Initial access / RDP | Security 4624 / 4625 | Successful and failed remote-interactive logons |
| PowerShell execution | Sysmon 1; PowerShell 4104 | Process command-line and script-block review |

> Event counts depend on the test run, time range, Windows audit policy,
> Sysmon configuration, and Splunk ingestion. Only publish counts that
> you have verified in your own search results.

---

## 🧠 Skills Demonstrated

- Splunk Enterprise configuration and Windows log ingestion
- Splunk Universal Forwarder deployment and troubleshooting
- Sysmon installation and endpoint telemetry collection
- SPL search, filtering, aggregation, and event correlation
- Authentication investigation and source-IP identification
- PowerShell process and script-block analysis
- Network reconnaissance investigation
- MITRE ATT&CK mapping
- SOC alert triage, timeline building, and documentation

---

## ⚙️ Lab Components

- Kali Linux VM
- Windows 10 VM (`MSEDGEWIN10`)
- Ubuntu Server running Splunk Enterprise
- Splunk Universal Forwarder on Windows
- Sysmon on Windows
- VMware Workstation virtual networking

### Data collection notes

- Windows events are forwarded to Splunk over TCP port **9997**.
- The lab's primary Splunk index is `main`.
- The Windows Universal Forwarder inputs are configured for selected
    Windows event channels, including Security, PowerShell Operational,
    and Sysmon Operational.
- Verify event IDs and field names against the raw events in your own
    Splunk instance before relying on a detection query.

---

## 📚 References

- [Splunk Documentation](https://docs.splunk.com/)
- [Splunk Search
    Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Microsoft Sysmon
    Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Security
    Auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)

---

## ⚠️ Disclaimer

This repository documents authorized security testing in a private home
lab for learning and defensive monitoring. Do not scan, test
authentication against, or attempt to access systems without explicit
permission. Results and event counts are environment-dependent.
