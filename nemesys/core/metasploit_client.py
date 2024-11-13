from nemesys.utils.logger import nemesysLogger
from pymetasploit3.msfrpc import MsfRpcClient

class MetasploitClient:
    def __init__(self, password, ssl=True):
        """
        Initializes the connection to Metasploit RPC client.

        Args:
            password (str): The password for authenticating with the Metasploit RPC service.
            ssl (bool): Flag to determine if SSL should be used for the connection (default is True).
        """
        try:
            # Establish connection to Metasploit
            self.client = MsfRpcClient(password, ssl=ssl)
            nemesysLogger.info("💀 Connection established: Metasploit is ready for action.")
        except Exception as e:
            # Log the error in case the connection fails
            nemesysLogger.error(f"❌ [METASPLOIT] Connection failed: {e}. Check if Metasploit is running and the password is correct.")
            self.client = None

    def get_client(self):
        """
        Returns the Metasploit RPC client instance.

        Returns:
            MsfRpcClient: The Metasploit RPC client object if connected, None otherwise.
        """
        if self.client:
            nemesysLogger.debug("🔐 [METASPLOIT] Returning connected Metasploit client.")
        else:
            nemesysLogger.warning("⚠️ [METASPLOIT] No active client. Unable to return client instance.")
        return self.client