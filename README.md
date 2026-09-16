# Cyber Trek

## Network Attack Detection and Threat Analysis Platform

Cyber Trek is a real-time Network Attack Detection and Threat Analysis Platform designed to monitor network activity, detect suspicious behavior, and visualize security events through an interactive dashboard.

The project combines network traffic monitoring, rule-based intrusion detection, explainable alerts, threat visualization, attack history management, and attack replay capabilities. It is intended as an educational and analytical platform for understanding cybersecurity monitoring and intrusion detection concepts.

---

## Features

* Real-time network traffic monitoring
* Rule-based attack detection
* Port Scan detection
* Brute Force attack detection
* DoS Flood detection
* SYN Flood detection
* ICMP Flood detection
* Explainable threat analysis
* Live alert generation
* Threat indicator panel
* Attack history logging
* Attack replay functionality
* Interactive dashboard
* Modular and extensible architecture

---

## System Workflow

```text
Network Traffic
       │
       ▼
Traffic Collection
       │
       ▼
Feature Extraction
       │
       ▼
Detection Engine
       │
       ▼
Attack Detection
       │
       ▼
Alert Generation
       │
       ▼
Dashboard Visualization
       │
       ▼
Attack History & Replay
```

---

## Technology Stack

### Frontend

* React
* Vite
* JavaScript
* HTML
* CSS

### Backend

* Python
* FastAPI

### Database

* SQLite

### Future Integrations

* PostgreSQL
* WebSockets
* Scapy
* Machine Learning Models
* Threat Intelligence APIs

---

## Project Structure

```text
src/
├── components/
│   ├── Dashboard
│   ├── TrafficFeed
│   ├── AlertPanel
│   ├── ThreatIndicators
│   ├── AttackHistory
│   └── ReplayModule
│
├── services/
│   ├── TrafficGenerator
│   ├── DetectionEngine
│   └── AlertManager
│
├── database/
│   └── SQLite
│
└── utils/
    └── DetectionRules
```

---

## Supported Attack Types

### Port Scan

Detects attempts to access multiple ports from the same source within a short period.

### Brute Force

Detects repeated authentication or connection attempts targeting a service.

### DoS Flood

Detects abnormal increases in packet rates that may indicate denial-of-service activity.

### SYN Flood

Detects excessive SYN requests compared to completed connections.

### ICMP Flood

Detects unusually high ICMP traffic volumes.

---

## Unique Features

### Explainable Detection

Instead of displaying only an alert, the system provides reasoning behind each detection, including thresholds, observed behavior, and confidence levels.

### Threat Visualization

Security events are represented through a dedicated dashboard and threat indicators for quick situational awareness.

### Attack Replay

Allows users to review the sequence of events that led to a detected attack.

### Educational Focus

Designed to help students and cybersecurity learners understand network intrusion detection concepts.
