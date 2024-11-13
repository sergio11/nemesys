from nemesys.core.exploit_manager import ExploitManager
from nemesys.core.metasploit_client import MetasploitClient
from nemesys.core.privilege_escalation_manager import PrivilegeEscalationManager
from nemesys.core.session_manager import SessionManager
from nemesys.core.shell_interface import ShellInterface
from nemesys.utils.logger import nemesysLogger
from nemesys import __version__

class Nemesys:
    def __init__(self, password, ssl=True, timeout=30):
        """
        Initializes the Nemesys facade class to manage the exploitation process.

        Args:
            password (str): Metasploit RPC client password.
            ssl (bool): Whether to use SSL when connecting to Metasploit.
            timeout (int): Timeout for waiting for sessions to become active.
        """
        self._print_banner()
        # Connect to Metasploit
        self.client = MetasploitClient(password, ssl).get_client()
        self.timeout = timeout

        if not self.client:
            nemesysLogger.error("❌ Connection to Metasploit failed.")
            return

        nemesysLogger.info("💀 Nemesys initialized and connected to Metasploit.")

        self.exploit_manager = ExploitManager(self.client)
        self.session_manager = SessionManager(self.client)
        self.shell_interface = ShellInterface(self.client, timeout=self.timeout)
        self.privilege_escalation_manager = PrivilegeEscalationManager(self.client)

    def run_attack(self, exploit_name, payload_name, exploit_options={}, payload_options={}, privilege_escalation_exploit=None, target=None):
        """
        Executes a specific attack with the chosen exploit and payload, performs privilege escalation, and handles post-exploitation tasks.
        
        Args:
            exploit_name (str): Name of the exploit module.
            payload_name (str): Name of the payload module.
            exploit_options (dict): Options for the exploit (e.g., RHOSTS, RPORT).
            payload_options (dict): Options for the payload (e.g., LHOST, LPORT).
            privilege_escalation_exploit (str, optional): Exploit module for privilege escalation.
            target (str, optional): IP address of the target (victim).
        """
        if not self.client:
            nemesysLogger.warning("⚠️ Client is not connected.")
            return None

        # Run the initial exploit
        nemesysLogger.info(f"💥 Executing exploit: {exploit_name} with payload: {payload_name}...")
        exploit_uuid = self.exploit_manager.run(exploit_name, payload_name, exploit_options, payload_options)
        if exploit_uuid:
            # Get session ID from the exploit result
            session_id = self.session_manager.get_session_id(exploit_uuid)
            if session_id:
                # Upgrade session
                new_session_id = self.session_manager.upgrade_session(session_id)
                if new_session_id:
                    self.session_manager.list_sessions()
                    # Perform privilege escalation if exploit provided
                    if privilege_escalation_exploit and target:
                        new_session_id = self.privilege_escalation_manager.run(new_session_id, privilege_escalation_exploit, target)
                        if new_session_id:
                            self.session_manager.list_sessions()
                    # Open interactive shell for further post-exploitation
                    self.shell_interface.open_shell(new_session_id)
                else:
                    nemesysLogger.error("❌ Session upgrade failed.")
            else:
                nemesysLogger.error("❌ No session was established.")
        else:
            nemesysLogger.error("❌ Exploit execution failed.")

    def _print_banner(self):
        """
        Prints a welcome banner at the start of the program for BlackVenom.
        """
        banner = f"""
        
        ██████   █████                                                             
        ░░██████ ░░███                                                              
        ░███░███ ░███   ██████  █████████████    ██████   █████  █████ ████  █████ 
        ░███░░███░███  ███░░███░░███░░███░░███  ███░░███ ███░░  ░░███ ░███  ███░░  
        ░███ ░░██████ ░███████  ░███ ░███ ░███ ░███████ ░░█████  ░███ ░███ ░░█████ 
        ░███  ░░█████ ░███░░░   ░███ ░███ ░███ ░███░░░   ░░░░███ ░███ ░███  ░░░░███
        █████  ░░█████░░██████  █████░███ █████░░██████  ██████  ░░███████  ██████ 
        ░░░░░    ░░░░░  ░░░░░░  ░░░░░ ░░░ ░░░░░  ░░░░░░  ░░░░░░    ░░░░░███ ░░░░░░  
                                                                ███ ░███         
                                                                ░░██████          
                                                                ░░░░░░           
        Nemesys: Critical Data Harvesting and Post-Exploitation Tool (Version: {__version__})
        """
        print(banner)