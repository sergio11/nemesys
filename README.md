# 💀 Nemesys: Critical Data Harvesting and Post-Exploitation Tool

**Nemesys** is an advanced exploitation and post-exploitation automation tool built on top of the Metasploit Framework. 🛠️ Designed for penetration testers and security researchers, it streamlines the process of targeting, exploiting, and deeply enumerating vulnerable systems. With a sleek dark-themed interface and powerful automation, **Nemesys** simplifies complex exploitation workflows, providing full control and visibility over compromised systems. ⚔️

🙏 I would like to express my sincere gratitude to [Santiago Hernández, a leading expert in Cybersecurity and Artificial Intelligence](https://www.udemy.com/user/shramos/). His outstanding course on **Cybersecurity and Ethical Hacking**, available on Udemy, was instrumental in the development of this project. The insights and techniques I gained from his course were invaluable in guiding my approach to cybersecurity practices. Thank you for sharing your knowledge and expertise!

### Disclaimer ⚠️
**Nemesys is intended for authorized and ethical use only**. Unauthorized use may result in severe legal consequences. Always have proper authorization before using this tool on any system.

<p align="center">
  <img src="https://img.shields.io/badge/langchain-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white" />
  <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue" />
</p>

<p align="center">
  <img src="doc/screenshots/picture_1.PNG" />
</p>

## 🚀✨ Key Features

- 🔍 **Automated Exploitation**: Execute Metasploit exploits effortlessly against target systems. Choose your desired exploit and payload, and let Nemesys automate the execution, session creation, and follow-up tasks.
- 🛡️ **Privilege Escalation**: Gain elevated access by leveraging built-in Metasploit modules for privilege escalation, enabling root or administrative control over the target system.
- ⬆️ **Session Upgrade to Meterpreter**: Automatically upgrades simple shell sessions to fully interactive Meterpreter sessions, unlocking additional post-exploitation capabilities such as file system browsing, keylogging, and pivoting.
- 💻 **Interactive Reverse Shell**: Establishes an interactive reverse shell with root or elevated privileges, enabling direct manual exploitation and in-depth system analysis.
- 🗂️ **System Critical Harvesting**: Conducts comprehensive system enumeration and data harvesting, extracting key details such as OS version, kernel information, network configuration, active processes, and user permissions.
- 🧠 **Intelligent Reporting with LLMs**: Utilizes **LangChain** integrated with **Groq** for cloud-based LLM processing. Generates a detailed analysis of the target system, including insights on potential next steps, vulnerability assessment, and remediation recommendations.
- 🤖 **Integration with Metasploit RPC**: Direct connection to Metasploit’s RPC interface allows efficient management of active sessions, payloads, and exploit modules, optimizing the post-exploitation workflow.
- 🛠️ **User-Friendly and Extensible**: Built with an intuitive interface for streamlined usage. Easily customizable to fit specific exploitation scenarios and to integrate with other tools in your security arsenal.

## 🔧💻 Requirements

- 🐍 **Python 3.8+** for running Nemesys scripts.
- 🦾 **Metasploit Framework** installed and configured.
- ☁️ **LangChain** and **Groq** access for cloud-based LLM processing.
- 🔑 **Root or Admin Privileges** for full functionality.

## 🛠️ Component Breakdown

Nemesys is designed with a modular architecture, where each component has a distinct responsibility, making the exploitation and post-exploitation process efficient and streamlined. Below is a detailed overview of each core component:

### 1. **MetasploitClient** 🕵️‍♂️

The **MetasploitClient** serves as the connection interface between Nemesys and the Metasploit RPC API.

- **Responsibilities**:
  - Establishes and manages the connection to the Metasploit RPC server.
  - Handles secure API requests with SSL support.
  - Provides a client object used by other components for unified Metasploit interactions.

- **Integration**:
  - Initiated during the setup of Nemesys to validate connectivity.
  - Essential for all interactions with Metasploit modules across components.

---

### 2. **ExploitManager** 💥

The **ExploitManager** handles the execution of exploits against target systems using Metasploit.

- **Responsibilities**:
  - Executes chosen exploit modules with specified payloads.
  - Configures options for both exploit and payload modules (e.g., `RHOSTS`, `LPORT`).
  - Tracks exploit attempts using UUIDs for result monitoring.

- **Integration**:
  - Triggered by the `run_attack()` method to start the exploitation phase.
  - Passes exploit UUIDs to the **SessionManager** for session tracking.

---

### 3. **SessionManager** 🔄

The **SessionManager** is in charge of managing sessions, including session upgrades and tracking active sessions.

- **Responsibilities**:
  - Retrieves session IDs based on the exploit UUID returned by the **ExploitManager**.
  - Upgrades standard shell sessions to Meterpreter sessions for enhanced capabilities.
  - Lists and manages active sessions for efficient exploitation.

- **Integration**:
  - Central to the transition between the exploitation and post-exploitation phases.
  - Handles session upgrades automatically and tracks session IDs.

---

### 4. **PrivilegeEscalationManager** 🔓

The **PrivilegeEscalationManager** focuses on elevating privileges after a session has been established.

- **Responsibilities**:
  - Identifies suitable privilege escalation exploits based on system information.
  - Executes privilege escalation modules (e.g., kernel exploits) to gain elevated access.
  - Verifies the success of privilege escalation attempts.

- **Integration**:
  - Optionally invoked in the `run_attack()` method if a privilege escalation module is specified.
  - Collaborates with the **SystemEnumerator** to determine potential escalation paths.

---

### 5. **ShellInterface** 🖥️

The **ShellInterface** provides an interactive shell for direct command execution on compromised targets.

- **Responsibilities**:
  - Opens an interactive shell session (Meterpreter or standard shell) for manual exploitation.
  - Supports system command execution, script imports, and file transfers.
  - Offers a user-friendly interface for further post-exploitation tasks.

- **Integration**:
  - Invoked at the end of the `run_attack()` process for hands-on interaction with the compromised system.
  - Adjusts the shell type based on the session capabilities (e.g., upgraded Meterpreter session).

---

### 6. **SystemEnumerator** 🔍

The **SystemEnumerator** is designed to gather extensive information about the compromised system for analysis.

- **Responsibilities**:
  - Collects system details such as OS version, network interfaces, installed software, and running processes.
  - Identifies potential vulnerabilities and misconfigurations using integrated tools like `searchsploit`.
  - Generates initial system assessment reports, aiding in further exploitation decisions.

- **Integration**:
  - Called after session establishment and upgrade to provide critical system information.
  - Supplies data to the **PrivilegeEscalationManager** for identifying privilege escalation opportunities.
  - Capable of generating advanced reports using **LangChain** with LLM analysis through Groq Cloud.

---

## 🧩 Workflow Overview

The main exploitation process in Nemesys involves the following steps:

1. **Initialization**:
   - Connects to Metasploit using **MetasploitClient**.

2. **Exploitation**:
   - Executes the chosen exploit and payload using **ExploitManager**.
   - Retrieves the session ID via **SessionManager**.

3. **Session Management**:
   - Upgrades the session for enhanced control.

4. **Privilege Escalation** (Optional):
   - Attempts privilege escalation using **PrivilegeEscalationManager**.

5. **System Enumeration**:
   - Gathers system information with **SystemEnumerator**.

6. **Interactive Shell**:
   - Provides a hands-on interactive shell through **ShellInterface** for manual exploitation.

---

This modular structure ensures that each component performs its role effectively, contributing to a cohesive and efficient exploitation workflow in Nemesys.

## ⚠️ Disclaimer
**Nemesys is intended for authorized and ethical use only**. Unauthorized use may result in severe legal consequences. Always have proper authorization before using this tool on any system.

## 🛡️ Legal
The author of Nemesys is not responsible for any misuse or damage caused by this tool. Use responsibly and comply with all local laws.

## 🖤 Contributing
Contributions are welcome! Feel free to submit issues or pull requests to help improve Nemesys.

## 💬 Contact
For any questions, suggestions, or feedback, reach out via GitHub or email.

## 🏴‍☠️ Happy Hacking!
