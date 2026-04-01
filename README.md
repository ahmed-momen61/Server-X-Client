# Bayezid Secure Server (Server-X-Client Milestones 1-3)

## Overview
This project implements a highly secure, multi-threaded TCP client-server communication system written in native C/C++ for Linux environments. Originally starting as a basic connection module, it has evolved into a robust architecture demonstrating advanced network programming, cryptography, Role-Based Access Control (RBAC), and active defense mechanisms against common cyber threats.

## Advanced Features
* **Multi-threaded Architecture:** Utilizes `pthread` to handle multiple concurrent client connections without blocking the main server execution.
* **Cryptographic Authentication (SHA-256):** Passwords are no longer stored in plaintext. The server validates credentials against SHA-256 hashes using the OpenSSL library.
* **Role-Based Access Control (RBAC):** Users are assigned specific access levels (Top, Medium, Entry) upon login, dynamically restricting their ability to execute commands (e.g., read, edit, delete).
* **Audit Logging:** Comprehensive tracking of all server events, authentications, executed commands, and security alerts, stored persistently in `server.log`.
* **Brute-Force Protection:** Automatically tracks failed login attempts and temporarily blocks the offending IP address after 3 consecutive failures.
* **Active Defense (Honeypot):** Deploys simulated restricted files (e.g., `passwords_backup.txt`). Unauthorized access attempts immediately trigger a critical alert, log the event, and kick the attacker off the server.
* **Graceful Shutdown:** Safely handles termination signals (like `Ctrl+C`), closes open sockets properly, and utilizes `SO_REUSEADDR` to prevent "Address already in use" errors upon restart.
* **Interactive Colored CLI:** A dynamic, terminal-based shell experience ("Bayezid-Shell") with color-coded feedback for success, warnings, and errors.

## Prerequisites
* A Linux-based environment (e.g., Ubuntu, Kali Linux).
* GCC Compiler (`g++`).
* OpenSSL Development Libraries.
  * *To install on Debian/Ubuntu:* `sudo apt-get install libssl-dev`

## Initial Setup
Before running the server, you must create a `users.txt` file in the same directory as the server executable. This file acts as your database. 

**Format:** `username hashedPassword role`

**Example `users.txt`:**
(Note: The hash below is for the password `mo2needs2sleep`)
```text
admin 744c8030bb4b791dc0c67efbc6e7cb359b3af3a8ed9c1488c036d0f5c1d1a63b Top
ahmed 744c8030bb4b791dc0c67efbc6e7cb359b3af3a8ed9c1488c036d0f5c1d1a63b Medium
guest 744c8030bb4b791dc0c67efbc6e7cb359b3af3a8ed9c1488c036d0f5c1d1a63b Entry