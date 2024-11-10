# 💀 Nemesys

**Nemesys** is a powerful, dark-themed tool designed to automate the exploitation and post-exploitation process using the Metasploit Framework. Ideal for penetration testers, it simplifies the process of discovering, exploiting, and enumerating vulnerable targets. ⚔️

## 🚀 Features
- **Automated Exploitation**: Seamlessly execute Metasploit exploits with preconfigured payloads.
- **System Enumeration**: Gather detailed information about the compromised target automatically.
- **Interactive Shell**: Gain full access to an interactive session for deeper manual control.
- **Extensive Logging**: All enumeration outputs are saved in a structured log file for later analysis.

## 🛠️ Prerequisites
- **Metasploit Framework**: Ensure Metasploit is installed and the RPC server (`msfrpcd`) is running.
- **Python 3.8+**: Nemesys requires Python 3.8 or higher.
- **Dependencies**:
  - `pymetasploit3`: A Python library for interacting with the Metasploit RPC API.

## 📦 Installation
1. Clone the repository.
2. Install dependencies using `pip install pymetasploit3`.
3. Configure your Metasploit RPC server with a username and password.

## 🕹️ Usage
- Edit the `main()` function to configure the exploit, payload, and options.
- Launch Nemesys using Python.
- Nemesys will automatically search for exploits, execute the chosen exploit, perform system enumeration, and open an interactive shell.

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