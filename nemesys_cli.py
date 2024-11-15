import argparse
import os
from dotenv import load_dotenv
from nemesys.nemesys import Nemesys

def main():
    # Load environment variables from the .env file
    load_dotenv()

    parser = argparse.ArgumentParser(description="Nemesys: Security Enumeration and Exploitation Tool")
    
    # Arguments for attack configurations
    parser.add_argument('--password', type=str, required=True, help="Password for the system (if applicable).")
    
    # Arguments for model and API key
    parser.add_argument('--model_id', type=str, help="Model ID to use for analysis (if not provided, will read from environment variable).")
    parser.add_argument('--groq_api_key', type=str, help="API key for Groq AI model (if not provided, will read from environment variable).")
    
    # Exploit arguments
    parser.add_argument('--exploit_name', type=str, required=True, help="The name of the exploit to run.")
    parser.add_argument('--payload_name', type=str, required=True, help="The name of the payload to use.")
    parser.add_argument('--rhosts', type=str, required=True, help="Target IP address for the exploit (RHOSTS).")
    parser.add_argument('--sitepath', type=str, required=True, help="Path for the exploit to use (SITEPATH).")
    
    # Payload options (e.g., reverse shell configuration)
    parser.add_argument('--lhost', type=str, required=True, help="Local IP address for the reverse payload (LHOST).")
    parser.add_argument('--lport', type=int, required=True, help="Local port for the reverse payload (LPORT).")
    
    # Privilege escalation exploit options
    parser.add_argument('--privilege_exploit', type=str, help="Privilege escalation exploit to use (e.g., PwnKit).")
    parser.add_argument('--target', type=str, required=True, help="Target system IP address.")
    
    args = parser.parse_args()

    # Read model ID and Groq API key from environment variables if not provided in command-line arguments
    model_id = args.model_id or os.getenv('MODEL_ID')
    groq_api_key = args.groq_api_key or os.getenv('GROQ_API_KEY')

    # Validate that both model_id and groq_api_key are provided
    if not model_id:
        print("Error: MODEL_ID is required. Provide it through --model_id or set the MODEL_ID environment variable.")
        return
    if not groq_api_key:
        print("Error: GROQ_API_KEY is required. Provide it through --groq_api_key or set the GROQ_API_KEY environment variable.")
        return

    # Instantiate Nemesys client
    client = Nemesys(password=args.password, model_id=model_id, groq_api_key=groq_api_key)

    # Set up exploit and payload configurations
    exploit_options = {
        'RHOSTS': args.rhosts,
        'SITEPATH': args.sitepath
    }
    payload_options = {
        'LHOST': args.lhost,
        'LPORT': args.lport
    }

    # Run the attack with the provided arguments
    try:
        print(f"Running attack: {args.exploit_name} with payload: {args.payload_name}")
        client.run_attack(
            exploit_name=args.exploit_name,
            payload_name=args.payload_name,
            exploit_options=exploit_options,
            payload_options=payload_options,
            privilege_escalation_exploit=args.privilege_exploit,
            target=args.target
        )
        print("Attack completed successfully.")
    except Exception as e:
        print(f"Error during attack: {e}")

if __name__ == "__main__":
    main()