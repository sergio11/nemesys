from nemesys.utils.logger import nemesysLogger
import time


class ShellInterface:
    """
    Interacts with an open shell session in Metasploit.

    This class allows for interacting with an active shell session,
    waiting for it to become active, and providing an interface for command execution.

    Attributes:
        client (MsfRpcClient): The Metasploit RPC client instance used to interact with the sessions.
        timeout (int): The maximum time (in seconds) to wait for a session to become active.
    """

    def __init__(self, client, timeout=30):
        """
        Initializes the class with the provided Metasploit client and timeout.

        Args:
            client (MsfRpcClient): The Metasploit RPC client used to interact with the sessions.
            timeout (int): Maximum time (in seconds) to wait for the session to become active. Default is 30 seconds.
        """
        self.client = client
        self.timeout = timeout

    def open_shell(self, session_id):
        """
        Main method to interact with an active shell session.

        This method waits for the specified session to become active, and then provides an interactive
        interface to send commands to the shell.

        Args:
            session_id (int): The session ID of the shell to interact with.

        Returns:
            None
        """
        # Try to obtain the session and wait for it to become active
        shell = self._wait_for_session(session_id)
        if not shell:
            return

        # Get session details
        is_meterpreter = self._check_meterpreter(session_id)

        # Show the shell interface banner
        self._show_banner()

        try:
            # Interactive shell interface
            self._interactive_shell(shell, is_meterpreter)

        except KeyboardInterrupt:
            nemesysLogger.info("👋 Exiting interactive session due to KeyboardInterrupt.")

    def _wait_for_session(self, session_id):
        """Waits for the specified session to become active."""
        end_time = time.time() + self.timeout
        shell = None
        while time.time() < end_time:
            try:
                # Try accessing the session
                shell = self.client.sessions.session(str(session_id))
                nemesysLogger.info(f"💀 Session {session_id} is now active!")
                break
            except KeyError:
                nemesysLogger.info(f"⏳ Waiting for session {session_id} to become available...")
                time.sleep(1)

        if not shell:
            nemesysLogger.error(f"❌ Session ID {session_id} does not exist after waiting.")
        return shell

    def _check_meterpreter(self, session_id):
        """Checks if the session is a Meterpreter session."""
        session_info = self.client.sessions.list.get(str(session_id), {})
        is_meterpreter = session_info.get('type', '').lower() == 'meterpreter'
        return is_meterpreter

    def _show_banner(self):
        """Displays the welcome banner for the shell interface."""
        banner = """
        ╔════════════════════════════════════════════════════════════╗
        ║            💀 Welcome to the Nemesys Shell Interface 💀   ║
        ║────────────────────────────────────────────────────────────║
        ║  ⚔️  Your gateway to post-exploitation and system control.║
        ║  🔍  Type 'help' for available commands.                   ║
        ║  🚪  Type 'exit' to leave the interactive session.         ║
        ╚════════════════════════════════════════════════════════════╝
        """
        nemesysLogger.info(banner)

    def _interactive_shell(self, shell, is_meterpreter):
        """
        Provides an interactive interface to send commands to the shell.

        This method reads user commands and executes them on the shell session. 
        Depending on whether the session is Meterpreter or not, different informational commands are used.

        Args:
            shell (MetasploitSession): The active shell session.
            is_meterpreter (bool): Indicates whether the session is Meterpreter.

        Returns:
            None
        """
        while True:
            # Get information about the user and current directory
            user, directory = self._get_user_directory(shell, is_meterpreter)

            # Build the prompt
            prompt = f"{user}@victim:{directory}$ "
            command = input(prompt)

            if command.lower() == 'exit':
                nemesysLogger.info("👋 Exiting interactive session.")
                break

            # Send the command to the shell
            self._send_command(shell, command)

    def _get_user_directory(self, shell, is_meterpreter):
        """Gets the user and current directory from the session."""
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

        return user, directory

    def _send_command(self, shell, command):
        """Sends a command to the shell and logs the output."""
        shell.write(command + '\n')
        time.sleep(1)
        output = shell.read()

        nemesysLogger.info(output)