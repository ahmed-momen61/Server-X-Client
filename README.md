# Server-X-Cient (Milestone 1)

## Overview
This project implements a secure, foundational TCP client-server communication system written in native C/C++ for Linux environments. It demonstrates fundamental network programming concepts along with a custom security module that ensures stable, authenticated, and encrypted data transmission.

## Features
* **TCP Socket Programming:** Reliable connection between a single client and server.
* **Pre-Shared Key (PSK) Authentication:** The server enforces a strict handshake protocol. Clients must authenticate with a valid password before any data exchange occurs.
* **Interactive CLI:** A dynamic command-line interface that prompts users for credentials, encryption preferences, keys, and messages at runtime.
* **Symmetric Encryption Layer:** Implements a custom XOR cipher. The user can optionally encrypt the payload with a secret key on the client side, which the server will then require to decrypt the received message.

## Prerequisites
* A Linux-based environment (e.g., Ubuntu).
* GCC Compiler (`g++`).

## Build Instructions
Open your terminal and compile the source files using `g++` then Run the Server --> Client {password:- mo2needs2sleep}:

```bash
g++ server.cpp -o server
g++ client.cpp -o client
./server
./client
*password*
make ur choices
