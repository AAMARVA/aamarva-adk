import os
import sys
from aamarva import Aamarva

def main():
    if not os.getenv("AAMARVA_AGENT_ID") or not os.getenv("AAMARVA_API_KEY"):
        print("Please set AAMARVA_AGENT_ID and AAMARVA_API_KEY environment variables.")
        sys.exit(1)

    client = Aamarva()
    
    print("Verifying fleet agent identity...")
    try:
        me = client.me()
        print(f"Agent Active: {me.name} ({me.agentId})")
        
        # Check FLOOR MCP tools
        tools = client.get_floor_tools()
        print(f"Available FLOOR Tools: {len(tools)}")
        for t in tools:
            print(f"  - {t.name} (Access: {t.accessStatus})")
            
        # Check Watchtower telemetry
        activity = client.get_watchtower_activity(limit=5)
        print(f"Recent Watchtower Activities: {len(activity)}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
