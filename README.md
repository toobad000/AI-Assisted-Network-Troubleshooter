# AI-Assisted Network Troubleshooter & ML Intrusion Detection System

A capstone project combining a rule-based AI diagnostic engine, a machine learning IDS, and a real-time telemetry pipeline, all integrated into a GNS3-simulated network environment with a graphical dashboard.

---

## Overview

This project automates network fault detection and remediation using a rule-based AI engine capable of diagnosing 26 distinct network configuration problems across OSPF, EIGRP, and interface states. The system is paired with a hybrid ML intrusion detection system that monitors live traffic for OSPF flood and SYN flood attacks, all surfaced through a real-time GUI dashboard.

The rule engine is designed to **dynamically expand its knowledge base** with each diagnostic run, improving fault identification and remediation accuracy over time as it gains more contextual insight on the network topology.

---

## Table of Contents

- [Overview](#overview)
- [Rule-Based AI Troubleshooter](#rule-based-ai-troubleshooter)
- [Telemetry Pipeline and GUI](#telemetry-pipeline-and-gui)
- [Machine Learning IDS](#machine-learning-ids)
- [System Architecture](#system-architecture)
- [Project Structure](#project-structure)
- [Results](#results)
- [Recommendations for Future Work](#recommendations-for-future-work)

---

## Rule-Based AI Troubleshooter

![Network Troubleshooter Dashboard](https://raw.githubusercontent.com/toobad000/AI-Assisted-Network-Troubleshooter/main/images/network-tshooter1.png)

### Capabilities

- Diagnoses **26 verified network problems** across:
  - 10 EIGRP configuration issues
  - 13 OSPF configuration issues
  - 3 interface-level issues
- Automatically pushes configuration fixes to devices via Telnet
- Maintains a versioned config history with rollback support
- Mines new compound rules from past diagnostic runs
- Scores detected problems with certainty factors and sequences fixes by confidence

### How It Works

#### 1. Discovery and Config Retrieval

On startup, `runner.py` scans the topology for all active routers and opens concurrent Telnet sessions to each one simultaneously. For every device, it retrieves the running configuration alongside targeted `show` commands (`show ip ospf`, `show ip eigrp neighbors`, `show ip interface brief`, etc.). This output is the raw input to the detection pipeline.

#### 2. Detection Trees

The retrieved output is passed through protocol-specific decision trees (`ospf_tree.py`, `eigrp_tree.py`, `interface_tree.py`). These trees check for the full range of general OSPF and EIGRP faults: interfaces that are administratively down when they should be up, neighbor relationships that have dropped, hello/dead timer mismatches, incorrect router IDs, missing or extra network statements, passive interface misconfigurations, stub area conflicts, AS number mismatches, and non-default K-values, among others. Any deviation from expected state is flagged as a detected problem with associated symptom fields extracted from the output.

#### 3. Topology-Aware Fix Selection via the Knowledge Base

Most routing problems are not black and white. A dropped OSPF neighbor could be caused by a timer mismatch, an area ID conflict, a passive interface, a duplicate router ID, or an authentication issue. The correct fix depends entirely on the topology context: whether a stub should exist in that location, which area a given interface belongs to, what the expected router ID is for that device.

To handle this, the system maintains a configuration versioning system (`config_manager.py`) that stores a known-good stable baseline for every device. When a problem is detected, the current configuration is compared against this baseline to extract the expected values and inform the fix.

The knowledge base (`knowledge_base.json`) is a structured set of problem-to-fix rule mappings. Each rule contains the problem type, the IOS commands needed to resolve it, a verification command, a confidence score, a success/attempt history, and optionally a device-specific context tag. For example:

- `OSPF_002` maps a hello interval mismatch to `ip ospf hello-interval` and `ip ospf dead-interval` commands, with a confidence of `0.99` earned over 18 successful applications
- `CTX_R3_003` is a context-specific variant of the same EIGRP timer fix, scoped to R3, with a `1.0` confidence score backed by 7 successful runs on that specific device

Rules fall into three tiers: base rules (hand-authored), mined rules (auto-generated from run history, prefixed `MINED_`), and context-specific rules (device-scoped, prefixed `CTX_`). IDS security response rules (`IDS_TCP_001`, `IDS_OSPF_001`) are also stored here and trigger interface shutdowns on detected attack traffic.

#### 4. Inference Engine and Fix Ranking

The inference engine (`inference_engine.py`) queries the knowledge base for all candidate rules matching the detected problem type and device. It ranks candidates by confidence score and selects the highest-confidence rule that meets a minimum tier threshold. If no rule clears the threshold, the fallback is a baseline revert: the system proposes restoring the affected device to its last known stable configuration rather than guessing.

Each fix decision produces a full explanation trace visible in the GUI, showing the reasoning path, the selected rule, its confidence level and tier, and all alternatives that were considered and rejected.

![Inference Engine Explanation Trace](https://raw.githubusercontent.com/toobad000/AI-Assisted-Network-Troubleshooter/main/images/IEtrace.png)

#### 5. Fix Application and Verification

`fix_applier.py` connects to the target device via Telnet and pushes the selected IOS commands. After applying the fix, it runs the rule's verification command (`show ip eigrp neighbors`, `show ip ospf`, etc.) and checks the output against expected state. The result, including success or failure, commands used, and verification output, is logged to the run history.

#### 6. Post-Run Learning and Rule Mining

After each diagnostic run, every rule that was invoked has its `attempts` and `successes` counters updated, and its confidence score is recalculated accordingly. The rule miner (`rule_miner.py`) then analyzes the run history looking for recurring problem-fix patterns that don't yet have a dedicated rule. When a pattern meets the support and success-rate thresholds, a new rule is automatically created and added to the knowledge base.

Over time, generalized rules gain device-specific context variants. A base rule like "if EIGRP stub present and should not be, remove it" may produce a `CTX_R2_004` variant scoped specifically to R2 with a higher confidence score reflecting its track record on that device. This makes the system progressively faster and more precise without expanding a context window: instead of replaying history each time, the learned context is baked directly into compact, targeted rules that execute in constant time.

---

## Telemetry Pipeline and GUI

![Telemetry Dashboard](https://raw.githubusercontent.com/toobad000/AI-Assisted-Network-Troubleshooter/main/images/tele1.png)

### Dashboard 
A structured dashboard shows live network statistics and alerts. 

In addition to on-demand diagnostic scans, the system detects and alerts on network events in real time. Unauthorized configuration changes, neighbor adjacency drops, and interface state changes automatically trigger alerts to the dashboard. This simulates a realistic threat scenario where an attacker has gained access to the network and is maliciously modifying device configurations. Each alert appears in the dashboard with device, event type, and severity, and clicking any alert directly launches the troubleshooter against the affected device, allowing the issue to be diagnosed and remediated in one step.

**Key Panels:**

- **Real-Time Progress Log** - live feed of all changes being applied to the network
- **Active Device Panel** - shows which devices are currently reachable
- **Live Network Status** - CPU usage, bandwidth, and performance per device
- **IDS Alert Log** - displays triggered alerts with severity levels
- **Integrated Troubleshooting** - execute ping, traceroute, or any command directly from the GUI to any device
- **Config History Browser** - browse past configurations and roll back to any previous state
- **Telemetry Data Panel** - live view of all telemetry data flowing through the pipeline

**SNMP** polls devices for bandwidth utilization, CPU load, memory usage, and interface errors  
**Syslog** receives push notifications whenever a configuration change is made on a device, enabling detection of threat-actor modifications  
**Telegraf** normalizes raw SNMP OIDs and Syslog streams into structured data and keeps a port open to receive incoming Syslog messages  
**InfluxDB** stores all telemetry data, enabling real-time monitoring, filtering, and graphing of network health  
```
GNS3 Devices
     │
     ├── SNMP (pull) ──────────────┐
     │                             ▼
     └── Syslog (push) ──► Telegraf ──► InfluxDB ──► GUI / AI
```
> Previous stack (Flask + Prometheus) was replaced due to added complexity, higher resource consumption, and slower AI response times.

---

## Machine Learning IDS

A hybrid IDS combining two models for complementary attack coverage.

### Models

| Model | Method | Accuracy | Target Attack |
|-------|--------|----------|---------------|
| **Random Forest** | Flow-level (NFStreamer) | 99% | OSPF flood |
| **Naive Bayes** | Packet-level (Scapy) | 93% | SYN TCP flood |

### How It Works

**Random Forest** uses NFStreamer to analyze traffic behavior over time rather than individual packets. An idle timeout breaks long-running streams into segments, letting the model distinguish a normal OSPF 10-second hello interval from 1,000 hellos in the same window. Fields like `src_ip` and `src_port` are intentionally omitted so the model generalizes to new attacker addresses.

**Naive Bayes** inspects individual packet-level features via Scapy: packet length, TCP/UDP flags, port numbers, and header sizes. It can flag anomalies like a SYN packet with no data payload.

### Dataset

- **7,000 rows** of labeled network traffic (up from an initial 3,100)
- Traffic diversity: ICMP echo, SSH/Telnet sessions, OSPF hellos, and attack flows with varied arrival times and packet sizes
- Timing-based label encoding: OSPF attacks flagged when mean PIAT drops below 1,000 ms; ICMP attacks below 100 ms

### Overfitting Check

| Set | Accuracy |
|-----|----------|
| Training | 100% |
| Testing | 99% |

The near-identical scores indicate the model has learned generalizable patterns rather than memorizing training data. Additional attack types are recommended for continued validation.

---

## System Architecture

```
╔══════════════════════════════════════════════════════════════════╗
║                          HOST MACHINE                            ║
║                                                                  ║
║   GNS3 Simulation                  ML IDS                        ║
║   (Network Topology) ─────────────(Random Forest + Naive Bayes) ║
║          │                                                       ║
║          │ Cloud Interface (Host Bridge)                         ║
║          │                                                       ║
║  ╔═══════╪══════════════════════╗  ╔═══════════════════════════╗ ║
║  ║       │    UBUNTU VM         ║  ║        KALI LINUX VM      ║ ║
║  ║       │                      ║  ║                           ║ ║
║  ║  ┌────┴──────────┐           ║  ║  ┌─────────────────────┐  ║ ║
║  ║  │ Rule-Based AI │           ║  ║  │   Attack Simulation │  ║ ║
║  ║  └───────────────┘           ║  ║  │  (OSPF Flood,       │  ║ ║
║  ║                              ║  ║  │   SYN Flood)        │  ║ ║
║  ║  ┌───────────────┐           ║  ║  └─────────────────────┘  ║ ║
║  ║  │ Flask Web App │           ║  ║                           ║ ║
║  ║  └───────────────┘           ║  ╚═══════════════════════════╝ ║
║  ║                              ║                               ║
║  ║  ┌───────────────────────┐   ║                               ║
║  ║  │  Telemetry Pipeline   │   ║                               ║
║  ║  │  SNMP  → Telegraf     │   ║                               ║
║  ║  │  Syslog → Telegraf    │   ║                               ║
║  ║  │  Telegraf → InfluxDB  │   ║                               ║
║  ║  └───────────────────────┘   ║                               ║
║  ╚══════════════════════════════╝                               ║
╚══════════════════════════════════════════════════════════════════╝
```

![GNS3 Network Topology](https://raw.githubusercontent.com/toobad000/AI-Assisted-Network-Troubleshooter/main/images/top1.png)

---

## Project Structure

```
Capstone_RuleBasedAI/
├── config_parser.py          # Parses device configs for baseline values
├── runner.py                 # Main orchestrator
├── core/
│   ├── advanced_analytics.py # Cross-device correlation and root cause tracing
│   ├── certainty_factors.py  # Problem confidence scoring
│   ├── config_manager.py     # Config save/load/versioning
│   ├── inference_engine.py   # Symptom-to-diagnosis reasoning
│   ├── knowledge_base.py     # Rules and learned facts
│   └── rule_miner.py         # Automatic rule generation from run history
├── detection/
│   ├── eigrp_tree.py
│   ├── interface_tree.py
│   ├── ospf_tree.py
│   └── problem_detector.py
├── history/
│   ├── configs/              # Stable device config snapshots
│   ├── knowledge/            # knowledge_base.json
│   └── runs/                 # Past run logs
├── resolution/
│   ├── fix_applier.py        # Telnet-based fix execution
│   └── fix_recommender.py    # Ranked fix generation
└── utils/
    ├── network_utils.py
    ├── reporter.py
    └── telnet_utils.py
```

---

## Environment

| Component | Purpose |
|-----------|---------|
| **GNS3** | Network simulation with real router/switch images |
| **VMware + Ubuntu VM** | Host environment for running all tooling |
| **Kali Linux VM** | Attack simulation (OSPF flood, SYN flood) |
| **Python** | Core language for AI, IDS, and telemetry components |
| **Wireshark** | Traffic capture for IDS dataset creation |
| **NFStreamer** | Flow-level feature extraction for Random Forest model |
| **Scapy** | Packet-level feature extraction for Naive Bayes model |
| **GitHub** | Version control and collaboration |

---

## Results

| Component | Outcome |
|-----------|---------|
| Rule-Based AI | 26/26 problem types diagnosed and resolved with 100% verified accuracy |
| Random Forest IDS | 99% test accuracy on OSPF flood detection |
| Naive Bayes IDS | 93% test accuracy on SYN flood detection |
| Telemetry Pipeline | SNMP + Syslog + Telegraf + InfluxDB fully operational |
| GUI | All panels functional with live data integration |

---

## Recommendations for Future Work

- Containerize and Optimize architecture for easier deployment
- Deploy on physical enterprise hardware for a stable and consistent topology
- Expand the IDS dataset with additional attack types and more varied traffic profiles
- Resolve Naive Bayes false positives through threshold tuning or feature refinement
- Continue expanding the rule engine beyond the current 26 problem types
