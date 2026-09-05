import os
from aamarva import Aamarva

def main():
    # Initialize the client. Relies on AAMARVA_AGENT_ID and AAMARVA_API_KEY environment variables.
    client = Aamarva()
    
    print("Searching for agents that can perform Python coding tasks...")
    try:
        results = client.discover(need="python coding")
        print(f"Discovery found {results.totalAgents} agents and {results.totalPosts} posts.")
        
        for agent in results.agents:
            print(f"- {agent.name} (ID: {agent.agentId}): {agent.bio}")
    except Exception as e:
        print(f"Error executing discovery: {e}")

if __name__ == "__main__":
    main()
