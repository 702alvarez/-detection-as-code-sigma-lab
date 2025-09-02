# 🛡️ Detection as Code — Sigma ➝ Kusto Lab

This project showcases an end-to-end Detection-as-Code (DaC) pipeline: authoring Sigma rules, converting them into KQL (Kusto Query Language) with the Sigma CLI, and validating detections inside a Windows lab environment before deployment to Azure Sentinel, Microsoft Defender, or ADX.

It highlights how security detections can be treated like software—automated, tested, version-controlled, and continuously improved—demonstrating both technical skill and modern detection engineering practices.

- Apply **Detection as Code** methodology  
- Author Sigma rules with UUIDs, MITRE ATT&CK tags, and namespaces  
- Automate Sigma ➝ KQL conversion using **Sigma CLI**  
- Validate detections by generating **benign test telemetry**  
- Deploy to Sentinel as Analytics rules (manual → IaC ready)  
- Document detections with **playbooks and triage guides** 

---

<img width="850" height="350" alt="Screenshot 2025-09-02 001015" src="https://github.com/user-attachments/assets/317cbc9a-d510-44c6-aa18-75d9f7e6e09b" />

---

## ⚙️ Lab Environment

- **Platform**: VMware Workstation Pro  
- **Guest VMs**:  
  - Windows 11 (authoring + test telemetry)  
  - Windows Server (domain controller + log collection)  
  - Ubuntu Server (optional log forwarder)  
- **Tools**:  
  - Python 3.11  
  - Sigma CLI (`pysigma`, `pysigma-backend-kusto`, `pysigma-pipeline-windows`)  
  - Visual Studio Code  
  - Sysmon for Windows event logging  
  - Git & GitHub  

---

## 📂 Repository Structure

🔗 [Detection-as-Code Project Files](https://github.com/702alvarez/detection-as-code)


```plaintext
detection-as-code/
├── detections/
│   ├── sigma/      # Sigma rules (source of truth)
│   │   └── windows/
│   │       └─ powershell_encoded_command.yml
│   │       
│   │       
│   └── kusto/      # Converted KQL queries
│       ├── powershell_encoded_command.kql
│       ├── certutil_download.kql
│       └── lolbin_suspicious.kql
├── tools/
│   └── convert_kusto.py   # Conversion script
└── docs/
    └── playbooks/         # Triage/response guides
```
---

## 📝 Step 1 — Author Sigma Rules

Sigma rules are written in YAML, including required metadata like `id` (UUID), `tags` (MITRE ATT&CK + namespace), and detection logic.

### Example: PowerShell EncodedCommand

```yaml
title: PowerShell EncodedCommand Usage
id: c4a0c1f0-1a9a-4b9a-ae5f-1a9a2b7d47b2
status: test
description: Detects PowerShell launched with -EncodedCommand (common obfuscation).
author: Anthony Alvarez
date: 2025/09/01
tags:
  - attack.t1059.001
  - os.windows
  - tool.powershell
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
falsepositives:
  - admin scripts
level: medium
```
---

## 🔄 Step 2 — Convert Sigma ➝ KQL with CLI

The Sigma CLI was used to convert Sigma rules into KQL queries:

```powershell
sigma convert --target kusto detections\sigma -o detections\kusto
```
This automatically generated .kql queries from the .yml Sigma rules.
---

## 🔍 Step 3 — Converted KQL Example

```kusto
DeviceProcessEvents
| where FolderPath endswith "\\powershell.exe" and (ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-EncodedCommand")
```
---
🧪 Step 4 — Validation with Benign Activity

Benign test commands executed to trigger detections:
```powershell
# PowerShell EncodedCommand
$script='Write-Output "HelloFromLab"'
$bytes=[Text.Encoding]::Unicode.GetBytes($script)
$enc=[Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $enc
```
---
## 📖 Step 5 — Playbooks

Each detection includes a mini triage guide.

<img width="500" height="250" alt="Screenshot 2025-09-02 000425" src="https://github.com/user-attachments/assets/f8aa6d7a-d81c-4738-b9f8-9a9a87452a5b" />


## 🚀 Step 6 — Deployment to Sentinel

Go to Sentinel → Analytics → Create Scheduled Query Rule

Paste KQL into query editor

Set Query frequency = 5m, Lookup period = 5m

Map entities (Host, Account)

Enable Incident creation

Save and test

<img width="800" height="400" alt="Screenshot 2025-09-01 221041" src="https://github.com/user-attachments/assets/4a6fa776-ddb7-41b3-a647-e8ad2fa2b471" />



## 🏆 Key Outcomes

Authored a Sigma rules tied to a MITRE ATT&CK technique

Converted rules to KQL using the Sigma CLI

Validated detections against real telemetry

Created playbooks for SOC analysts

Demonstrated end-to-end DaC workflow 
