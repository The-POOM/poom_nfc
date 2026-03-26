# NFC Application

This application provides the main NFC interaction layer for the firmware.

Its purpose is to offer a practical environment for NFC discovery, card detection, device interaction, protocol testing, tuning, and experimentation workflows. It is intended to act as the high-level application layer built on top of the project’s NFC subsystem.

## Purpose

This application is designed to support common NFC workflows such as:

- starting and stopping the NFC runtime,
- scanning for nearby NFC devices,
- identifying and classifying detected cards,
- connecting to compatible targets,
- exchanging raw data for testing and diagnostics,
- supporting lab-oriented tuning and validation tasks,
- serving as a foundation for future reader and emulation scenarios.

## Scope

At a high level, this application is responsible for coordinating the NFC experience exposed to the rest of the firmware.

This includes:

- lifecycle control of the NFC application,
- reader-oriented scanning and activation flows,
- card identification and probing,
- raw communication and protocol experimentation,
- support utilities for testing and development,
- configuration and control paths for advanced NFC workflows.

## Structure

```text
applications/nfc_read
├── include/
└── src/
````

The code is organized into multiple modules so that core control, reader behaviour, card handling, protocol-specific logic, tuning, and advanced runtime features remain separated and easier to maintain.

## Design Goals

* **Modular**: keep different NFC responsibilities separated.
* **Reusable**: allow the application to be extended by other firmware features.
* **Practical**: support real test and integration workflows.
* **Scalable**: serve as a base for more advanced NFC capabilities over time.
* **Maintainable**: keep high-level application logic clean and structured.

## What This Application Enables

This application is intended to make it possible to:

* discover NFC cards and tags,
* inspect and identify detected devices,
* establish communication with supported targets,
* test raw exchanges in a controlled environment,
* validate behaviour during development,
* support local diagnostics and tuning workflows,
* provide a usable base for future expansion.

## High-Level Flow

In general, the application follows a flow like this:

1. Start the NFC application runtime.
2. Scan for nearby NFC devices.
3. Detect and identify available targets.
4. Activate or connect to a selected device.
5. Exchange data or perform the desired operation.
6. Stop the NFC session or return to idle.

## Intended Use

This application is mainly aimed at:

* development workflows,
* integration testing,
* lab validation,
* debugging and diagnostics,
* controlled experimentation with NFC interactions.

## Summary

In short, this application is the high-level NFC reader layer of the firmware. It provides the logic needed to turn the lower-level NFC subsystem into a usable runtime feature for scanning, identifying, interacting with, and testing NFC devices in a structured way.

