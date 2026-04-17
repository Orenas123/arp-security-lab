# ARP Security Lab

## Overview
ARP Security Lab is a cybersecurity research project focused on analyzing and simulating ARP-based Man-in-the-Middle (MITM) attacks in local networks. The system combines an ARP spoofing simulation module with a real-time detection and mitigation engine, demonstrating both offensive and defensive aspects of ARP protocol behavior.

This project is intended for educational and research purposes in network security and protocol analysis.

---

## System Architecture

The project is divided into two independent modules:

### 🔹 Attack Simulation Module
A controlled ARP spoofing environment that demonstrates how ARP cache poisoning can be performed within a local network.

**Capabilities:**
- Discovery of victim and gateway MAC addresses
- Continuous ARP reply injection (MITM simulation)
- Traffic interception behavior emulation
- Safe termination with automatic ARP table restoration

---

### 🔹 Defense & Monitoring Module
A real-time ARP monitoring system designed to detect and mitigate spoofing attempts.

**Capabilities:**
- Baseline ARP table generation (trusted mappings)
- Live ARP packet sniffing and analysis
- Detection of IP–MAC inconsistencies
- Multi-IP MAC anomaly detection
- Automatic ARP cache restoration
- Alert system with cooldown control
- Real-time GUI dashboard (Flet-based interface)

---

## Detection Logic

The defense system maintains a trusted mapping of:
IP → MAC

An alert is triggered when:
- A known IP address is associated with a different MAC address
- A single MAC address claims multiple IPs
- Unexpected ARP reply behavior is detected

Upon detection, corrective ARP packets are generated to restore the original network state.

---

## Technologies Used
- Python 3
- Scapy (packet crafting & sniffing)
- Flet (graphical interface)
- Threading (real-time processing)
- Queue-based event handling

---

## Key Features
- Dual-mode architecture (Attack / Defense)
- Real-time network packet inspection
- Automatic mitigation of ARP spoofing attempts
- Lightweight and modular design
- Educational simulation of MITM attack vectors

---

## Ethical Notice
This project is strictly intended for educational and controlled lab environments only. Unauthorized use of ARP spoofing techniques on networks without explicit permission is prohibited.

---

## Purpose
The goal of this project is to deepen understanding of:
- ARP protocol vulnerabilities
- Network-level attack vectors (MITM)
- Real-time detection strategies
- Defensive network security mechanisms

---

## Author Notes
This project demonstrates both offensive and defensive perspectives of ARP-based network behavior to support cybersecurity learning and research experimentation.
