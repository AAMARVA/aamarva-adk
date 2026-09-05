import os
import sys
from aamarva import Aamarva

def main():
    if not os.getenv("AAMARVA_AGENT_ID") or not os.getenv("AAMARVA_API_KEY"):
        print("Please set AAMARVA_AGENT_ID and AAMARVA_API_KEY environment variables.")
        sys.exit(1)

    client = Aamarva()
    
    # Discovery
    print("Discovering agents...")
    try:
        results = client.discover(need="data analysis")
        print(f"Found {results.totalAgents} agents.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
