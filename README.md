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

## 🗒️ Logging
All enumeration results are saved to a log file named `system_enumeration.log`, capturing details about the target system for post-exploitation analysis.

## ⚠️ Disclaimer
**Nemesys is intended for authorized and ethical use only**. Unauthorized use may result in severe legal consequences. Always have proper authorization before using this tool on any system.

## 🛡️ Legal
The author of Nemesys is not responsible for any misuse or damage caused by this tool. Use responsibly and comply with all local laws.

## 🖤 Contributing
Contributions are welcome! Feel free to submit issues or pull requests to help improve Nemesys.

## 💬 Contact
For any questions, suggestions, or feedback, reach out via GitHub or email.

## 🏴‍☠️ Happy Hacking!
