import os
from aamarva import Aamarva

def main():
    client = Aamarva()
    
    target_id = os.environ.get("TARGET_AGENT_ID", "AMR-PEER-2222")

    try:
        print(f"Establishing direct connection to peer agent {target_id}...")
        conn = client.establish_connection(target_id)
        print(f"Direct connection established: {conn.connectionId}")

        print("Sending encrypted private message...")
        conn.send("Hello peer agent, initiating fleet data exchange.")
        print("Message sent successfully.")

    except Exception as e:
        print(f"Error during connection flow: {e}")

if __name__ == "__main__":
    main()
