# SIEM Detection Lab — Azure Sentinel Home Lab

## Overview

This project documents building a working Security Operations Center (SOC) detection lab from scratch on Microsoft Azure. The goal: stand up a real SIEM (Microsoft Sentinel), connect a live log source, write detection queries in KQL, and build an automated analytics rule that catches suspicious activity, all using a free-tier Azure subscription.

**What this lab demonstrates:**
- Deploying and configuring Microsoft Sentinel as a SIEM
- Standing up a Windows Server VM as a monitored log source
- Ingesting Windows Security Event logs via a Data Collection Rule (AMA-based)
- Writing and saving KQL queries to detect failed logons, new user creation, and sign-in patterns
- Building a scheduled Analytics Rule that automatically detects and alerts on brute-force/password-spray activity
- Real troubleshooting: region mismatches, ingestion delays, and a genuinely obscure Sentinel–Defender permissions bug

---

## Architecture

```
Windows Server VM (VM-SOClab)
        │
        │  Azure Monitor Agent (AMA)
        ▼
Data Collection Rule (DCR-Windows)
        │
        ▼
Log Analytics Workspace (law-soc-lab)
        │
        ▼
Microsoft Sentinel (SIEM)
        │
        ▼
KQL Queries + Scheduled Analytics Rule → Alerts
```

---

## Phase 1 — Stand Up a SIEM

**Goal:** Deploy Microsoft Sentinel on a free Azure account and reach a running, logged-in workspace.

**What I did:**
1. Signed up for an Azure free trial ($200 credit).
2. Created a Resource Group: `RG-SOClab` (Region: Australia Central).
3. Created a Log Analytics Workspace: `law-soc-lab`, in the same region as the resource group.
4. Enabled Microsoft Sentinel on top of that workspace.
5. Confirmed I could reach the Sentinel Overview dashboard (Incidents / Automation tiles visible).

**Screenshots:**

Resource group created
<img width="1920" height="1080" alt="Resource group-DAY 15" src="https://github.com/user-attachments/assets/882dda3e-356e-417b-a8c2-6ddb1621b4ff" />


Log Analytics workspace deployed
<img width="1920" height="1080" alt="Log-DAY 15" src="https://github.com/user-attachments/assets/f5bf7744-2388-4cda-a852-ec2a55a9fa23" />


Sentinel Overview page live
<img width="1920" height="1080" alt="Sentinal DAY15" src="https://github.com/user-attachments/assets/4905f9d7-c42f-4cd6-bf24-b0e88501b286" />

**Outcome:** A fully provisioned, empty SIEM ready to receive log data.

---

## Phase 2 — Get Logs Flowing

**Goal:** Connect a real log source and confirm sign-in, process, and network events are arriving and searchable.

**What I did:**
1. Created a Windows Server 2022 VM (`VM-SOClab`) to act as the monitored endpoint.
2. Set up auto-shutdown to control free-trial costs.
3. Installed the **Windows Security Events** solution from the Sentinel Content Hub.
4. Created a **Data Collection Rule** (`DCR-Windows`):
   - Attached `VM-SOClab` as the source resource
   - Configured to collect Windows Event Logs → Security (Audit success + Audit failure)
   - Destination: `law-soc-lab` workspace
5. Confirmed the Azure Monitor Agent installed successfully ("Provisioning succeeded").
6. Generated real activity on the VM (sign-in/out cycles) and confirmed logs were searchable in Sentinel.

**Errors I hit and how I fixed them:**

| Problem | Cause | Fix |
|---|---|---|
| DCR destination search returned "No results were found" | The DCR's region (Australia Southeast) didn't match the workspace region (Australia Central) | Recreated the DCR in the same region as the workspace |
| `SecurityEvent \| take 10` returned no results | AMA-based DCRs write to the generic `Event` table, not the legacy `SecurityEvent` table | Queried the `Event` table instead, filtered by `Source == "Microsoft-Windows-Security-Auditing"` |
| No log data appeared for ~40 minutes after setup | Normal first-time ingestion delay for a brand-new VM/DCR pairing | Waited it out, verified locally in Windows Event Viewer that logs were generating (they were — confirming it was purely an Azure-side ingestion delay, not a config issue) |

**Screenshots:**

VM deployed
<img width="1920" height="1080" alt="same VM DAY16" src="https://github.com/user-attachments/assets/ca2a767b-ce83-4f66-809d-f695ed67a96f" />


Content Hub solution installed
<img width="1920" height="1080" alt="Windows security events (AMA) DAY16" src="https://github.com/user-attachments/assets/8ce509c0-d210-4090-8972-ce0f7d050ae3" />


Data Collection Rule created
<img width="1920" height="1080" alt="DCR created DAY16" src="https://github.com/user-attachments/assets/25a4cee7-d0af-4a1c-a07c-b50078143044" />


Logs confirmed flowing in Sentinel Logs
<img width="1920" height="1080" alt="Audit flowing-DAY16" src="https://github.com/user-attachments/assets/5daf546a-6e24-4069-ab96-7fccf5597b6e" />


**Outcome:** One live log source connected end-to-end, with real Security event data (including unsolicited RDP brute-force attempts from the open internet) flowing into Sentinel.

---

## Phase 3 — Learn to Query the Logs

**Goal:** Write KQL queries against the logs — failed logons, new users, unusual sign-ins — and save them.

**Queries built:**

**1. Failed logons**
```kql
Event
| where TimeGenerated > ago(7d)
| where Source == "Microsoft-Windows-Security-Auditing"
| where EventID == 4625
| take 20
```

**2. New user account creation**
```kql
Event
| where TimeGenerated > ago(7d)
| where Source == "Microsoft-Windows-Security-Auditing"
| where EventID == 4720
| take 20
```

**3. Successful sign-ins summary (unusual sign-in volume)**
```kql
Event
| where TimeGenerated > ago(7d)
| where Source == "Microsoft-Windows-Security-Auditing"
| where EventID == 4624
| summarize LoginCount = count() by Computer
| order by LoginCount desc
```

**What I learned along the way:**
- `ago(24h)` vs `between (datetime .. datetime)` for time filtering
- `summarize count() by` for aggregating results instead of listing every row
- `bin()` for bucketing timestamps into time windows (e.g., hourly)
- Why grouping by `TimeGenerated` directly breaks aggregation (every timestamp is unique, so nothing actually groups)

**Screenshots:**

New user query results
<img width="1920" height="1080" alt="Checking any new aacc on my VM DAY 17" src="https://github.com/user-attachments/assets/eb5bc69c-8191-4307-9ee7-2371c1db4bd0" />


Sign-in summary query results
<img width="1920" height="1080" alt="Checking every signin DAY 17" src="https://github.com/user-attachments/assets/087362a1-a814-417d-8666-0256057ac234" />


**Outcome:** Three saved, reusable KQL queries covering the core SOC analyst daily workflow.

---

## Phase 4 — Simulate and Detect

**Goal:** Generate suspicious activity and build an analytics rule that catches it automatically — not just a manual query, but a live, scheduled detection.

**What I did:**
1. Used real attack data — the VM's exposed RDP port (3389) was already attracting continuous brute-force login attempts from the internet, generating genuine failed-logon events.
2. Wrote the detection logic in KQL:
```kql
Event
| where Source == "Microsoft-Windows-Security-Auditing"
| where EventID == 4624
| summarize FailedCount = count() by Computer
| where FailedCount > 5
```
3. Built a **Scheduled Analytics Rule** named `Failed-Logon-Spray-Detection`:
   - Severity: Medium
   - Runs every 5 minutes, checking the last 5 minutes of data
   - Configured to generate alerts on match

**The big blocker — and how I fixed it:**

Microsoft had recently migrated Analytics rule creation from the classic Azure Sentinel interface into the **Microsoft Defender portal**. Every attempt to reach the Analytics page in Defender looped back to the Defender home screen — no matter which navigation path I used (sidebar, direct URL, different browser sessions, Incognito mode). This alone cost close to two hours.

I checked my Azure RBAC roles first (Access Control / IAM) and found I already had full **Owner** and **Microsoft Sentinel Contributor** access — so it wasn't a standard permissions problem.

The actual fix: Microsoft Defender XDR runs its **own separate permissions/activation layer**, independent of Azure RBAC, called MTP Unified RBAC. My Sentinel workspace showed as **"Not active"** under:
`Defender Portal → Settings → Microsoft Defender XDR → Microsoft Sentinel workspace management`

Clicking **"Activate workspaces"** there — a setting barely documented anywhere — immediately resolved the looping issue. Analytics rule creation worked right after.

**Verifying it actually worked:**
The Incidents page initially showed nothing, which was confusing since the rule and query were both confirmed correct. I checked **Advanced Hunting**, querying the `SecurityAlert` table directly:
```kql
SecurityAlert
| where AlertType has_cs "<rule-id>"
| order by TimeGenerated asc
```
This confirmed the rule **had been firing correctly** — three separate Medium-severity alerts triggered over the previous day, all correctly matching the failed-logon pattern. They weren't escalating to full "Incidents" due to Defender's built-in alert-tuning/filtering system suppressing them — a separate platform behavior, not a flaw in the detection logic itself.

**Errors I hit and how I fixed them:**

| Problem | Cause | Fix |
|---|---|---|
| Defender Analytics page looped back to home screen endlessly | Sentinel workspace not "activated" under Defender's own MTP Unified RBAC system (separate from Azure RBAC) | Went to Defender → Settings → Microsoft Defender XDR → Sentinel workspace management → clicked "Activate workspaces" |
| "Connect and set as primary" button greyed out in Defender SIEM settings | Same root cause as above | Resolved once workspace was activated |
| Rule appeared to fire zero incidents | Sentinel's "Rule runs" history has a built-in 90-minute display delay, and Defender's alert tuning was suppressing incident escalation | Verified via Advanced Hunting on the `SecurityAlert` table directly — confirmed the rule was working; incidents just weren't being escalated by Defender's filtering layer |

**Screenshots:**

RBAC role check (confirmed not the cause)
<img width="1920" height="1080" alt="Made microsoft sentinal contibutor to access analtyocs DAY 18" src="https://github.com/user-attachments/assets/01d74159-7320-4ff3-aba1-77b7fb14d409" />


Analytics rule created and enabled
<img width="1920" height="1080" alt="Failed logon spray detection rule DAY 19" src="https://github.com/user-attachments/assets/6d34d277-55d8-4a97-ae67-5b85ef18fa6a" />


Confirmed alerts firing via Advanced Hunting
<img width="1920" height="1080" alt="auto logs done  DAY 18" src="https://github.com/user-attachments/assets/bd00ce2f-ff97-408f-8298-f1f5ab963860" />


**Outcome:** A working, automated detection pipeline — attack data → detection query → scheduled rule → firing alerts — plus a genuinely valuable real-world troubleshooting story around Azure/Defender permission layers.

---

## Key Takeaways

- **A SIEM is only as good as its data pipeline** — region mismatches, table naming differences (`Event` vs `SecurityEvent`), and ingestion delays are all things a real analyst has to diagnose, not just configure once and forget.
- **Permissions aren't one system.** Azure RBAC and Microsoft Defender XDR's permission layer are separate — having full Owner access in one doesn't guarantee access in the other.
- **An empty result isn't always a failure.** Whether it's a "no new users created" query or a "no incidents yet" dashboard, the right response is to verify *why* before assuming something's broken.
- **Real attack data beats simulated data.** Leaving RDP open to the internet turned this lab into a live feed of genuine brute-force attempts — better detection-testing material than any synthetic script.

---

## Tech Stack

- Microsoft Azure (Free Trial)
- Microsoft Sentinel (SIEM)
- Log Analytics Workspace
- Azure Monitor Agent (AMA)
- Windows Server 2022
- KQL (Kusto Query Language)
- Microsoft Defender XDR

---

## Repository Structure

```
siem-soc-lab/
├── README.md
└── screenshots/
    ├── Phase1/
    ├── Phase2/
    ├── Phase3/
    └── Phase4/
```
