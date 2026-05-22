# AI-Assisted Network Troubleshooter & ML Intrusion Detection System

A capstone project combining a rule-based AI diagnostic engine, a machine learning IDS, and a real-time telemetry pipeline — all integrated into a GNS3-simulated network environment with a graphical dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Environment](#environment)
- [System Architecture](#system-architecture)
- [Rule-Based AI Troubleshooter](#rule-based-ai-troubleshooter)
- [Machine Learning IDS](#machine-learning-ids)
- [Telemetry Pipeline](#telemetry-pipeline)
- [Graphical User Interface](#graphical-user-interface)
- [Results](#results)
- [Lessons Learned](#lessons-learned)

---

## Overview

This project automates network fault detection and remediation using a rule-based AI engine capable of diagnosing 26 distinct network configuration problems across OSPF, EIGRP, and interface states. The system is paired with a hybrid ML intrusion detection system that monitors live traffic for OSPF flood and SYN flood attacks, all surfaced through a real-time GUI dashboard.

The rule engine is designed to **dynamically expand its knowledge base** with each diagnostic run, improving fault identification and remediation accuracy over time as it gains more contextual insight on the network topology.

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

## System Architecture

```
 ┌───────────────────────────────────────────────────────┐
 │                    Host Machine                       │
 │                                                       │
 │  ┌─────────────────────┐     ┌─────────────────────┐  │
 │  │      GNS3 Sim       │     │      ML IDS         │  │
 │  │  (Network Topology) │     │    (Random Forest   │  │
 │  └─────────┬───────────┘     │     + Naive Bayes)  │  │
 │            │ Cloud Interface  └─────────────────────┘ │
 │            │ (Host Bridge)                            │
 │  ┌─────────┴───────────────────────────────────────┐  │
 │  │                  Ubuntu VM                      │  │
 │  │                                                 │  │
 │  │  ┌──────────────┐   ┌───────────────────────┐   │  │
 │  │  │ Rule-Based AI│   │  Telemetry Pipeline   │   │  │
 │  │  └──────────────┘   │ SNMP → Telegraf →     │   │  │
 │  │                     │ InfluxDB              │   │  │
 │  │  ┌──────────────┐   │ Syslog → Telegraf     │   │  │
 │  │  │ Flask Web App│   └───────────────────────┘   │  │
 │  │  └──────────────┘                               │  │
 │  └─────────────────────────────────────────────────┘  │
 └───────────────────────────────────────────────────────┘
```

---

## Rule-Based AI Troubleshooter

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

1. `runner.py` connects to all devices and initiates a scan
2. Detection trees (`ospf_tree.py`, `eigrp_tree.py`, `interface_tree.py`) analyze device configs
3. The inference engine (`inference_engine.py`) applies rules from the knowledge base to diagnose problems
4. `fix_recommender.py` generates ranked fix recommendations
5. `fix_applier.py` connects via Telnet and pushes the fixes
6. The rule miner (`rule_miner.py`) updates the knowledge base from each run's outcome

### Project Structure

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

## Telemetry Pipeline

```
GNS3 Devices
     │
     ├── SNMP (pull) ──────────────┐
     │                             ▼
     └── Syslog (push) ──► Telegraf ──► InfluxDB ──► GUI / AI
```

- **SNMP** polls devices for bandwidth utilization, CPU load, memory usage, and interface errors
- **Syslog** receives push notifications whenever a configuration change is made on a device, enabling detection of threat-actor modifications
- **Telegraf** normalizes raw SNMP OIDs and messy Syslog streams into structured data and keeps a port open to receive incoming Syslog messages
- **InfluxDB** stores all telemetry data, enabling real-time monitoring, filtering, and graphing of network health

> Previous stack (Flask + Prometheus) was replaced due to added complexity, higher resource consumption, and slower AI response times.

---

## Graphical User Interface

The GUI replaces raw terminal output with a structured dashboard. Key panels:

- **Real-Time Progress Log** — live feed of all changes being applied to the network
- **Active Device Panel** — shows which devices are currently reachable
- **Live Network Status** — CPU usage, bandwidth, and performance per device
- **IDS Alert Log** — displays triggered alerts with severity levels
- **Integrated Troubleshooting** — execute ping, traceroute, or any command directly from the GUI to any device
- **Config History Browser** — browse past configurations and roll back to any previous state
- **Telemetry Data Panel** — live view of all telemetry data flowing through the pipeline

### Implementation Notes

Two major bugs were resolved during GUI development:

1. **Telnet buffer truncation** — a static timer caused the tool to stop reading configs before the full output was received, leading to false positives/negatives. Fixed by switching to prompt-based termination to guarantee 100% data integrity.
2. **UI thread freezing** — network scans were blocking the main thread. Resolved with a multithreaded architecture that offloads heavy operations to background threads with thread-safe UI updates.

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

- Deploy on physical enterprise hardware for a stable and consistent topology
- Expand the IDS dataset with additional attack types and more varied traffic profiles
- Resolve Naive Bayes false positives through threshold tuning or feature refinement
- Continue expanding the rule engine beyond the current 26 problem types
