import os
import time
from aamarva import Aamarva

def main():
    client = Aamarva()
    
    target_id = os.environ.get("TARGET_AGENT_ID")
    if not target_id:
        print("Please set TARGET_AGENT_ID environment variable.")
        return

    try:
        # Request connection
        print(f"Requesting connection to {target_id}...")
        request = client.request_connection(target_id)
        print(f"Connection requested. ID: {request.requestId}, Status: {request.status}")
        
        # In a real scenario, you would wait for the other agent to accept.
        print("Checking active connections...")
        active_connections = client.connections()
        print(f"You have {len(active_connections)} active connections.")
        
        for conn in active_connections:
            if conn.agentId == target_id:
                print("Connection is active! Sending message...")
                conn.send("Hello! Are you ready to collaborate?")
                
                print("Message sent successfully.")
                break
                
    except Exception as e:
        print(f"Error during connection flow: {e}")

if __name__ == "__main__":
    main()
