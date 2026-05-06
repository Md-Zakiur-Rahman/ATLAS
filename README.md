# ATLAS — Adaptive Threat Level Assessment & Security System

## Member B — Detection & Monitoring Core

Branch: `feature/detect-core`

---

# Project Overview

ATLAS (Adaptive Threat Level Assessment & Security System) is a Blue Team-oriented cybersecurity platform focused on:

* Real-time monitoring
* Threat detection
* Behavioral analysis
* Incident response
* Security event logging

This branch contains the Detection & Monitoring subsystem of the project.

---

# Technologies Used

## watchdog

Python library used for real-time filesystem monitoring.

Purpose:

* Detect file creation
* Detect file modification
* Detect file deletion
* Monitor filesystem activity in real time

---

## psutil

Python library used for process and system monitoring.

Purpose:

* Enumerate running processes
* Retrieve process information
* Support future suspicious process detection

---

## queue.Queue

Used for thread-safe event communication.

Purpose:

* Pass events safely between monitoring modules
* Support future integration with alert systems and dashboards

---

# Current Module Structure

```text id="jlwm157"
monitor/
│
├── file_monitor.py
├── process_monitor.py
├── event_bus.py
└── models.py
```

---

# Development Log

## Day 1 — Monitoring Foundation

### Completed Tasks

#### File System Monitoring

Implemented real-time filesystem monitoring using the Python watchdog library.

Features:

* File creation detection
* File modification detection
* File deletion detection
* Recursive directory monitoring

---

#### Event Bus System

Built a thread-safe event queue architecture for communication between monitoring components.

Features:

* Event publishing
* Queue-based event handling
* Thread-safe structure

---

#### Threat Severity Classification

Created a ThreatLevel enum for standardized threat categorization.

Current Levels:

* LOW
* MEDIUM
* HIGH
* CRITICAL

---

#### Event Logging Model

Implemented an EventLog dataclass for structured event handling.

Each event stores:

* Event type
* Severity
* Details
* Timestamp

---

#### Process Monitoring

Implemented a basic process monitoring system using psutil.

Features:

* Enumerates active processes
* Retrieves process names
* Retrieves process IDs (PID)

---

# Current Working Features

* Real-time filesystem monitoring
* Event publishing system
* Process enumeration
* Threat severity classification
* Structured event logging

---

# Current Status

## Completed

* Monitoring core foundation
* Process monitoring
* Event architecture
* Filesystem event capture

## In Progress

* Threat detection engine

---
