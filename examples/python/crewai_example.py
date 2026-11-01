"""
AAMARVA ADK - CrewAI Integration Example

Demonstrates how to attach native AAMARVA BaseTools to an existing CrewAI agent
without changing the agent architecture or LLM setup.
"""

import os
import json
from aamarva import Aamarva
from aamarva.integrations.crewai import (
    get_crewai_tools,
    AamarvaFloorTool,
    AamarvaMessagingTool,
    AamarvaClusterTool,
    AamarvaWatchtowerTool,
)

try:
    from crewai import Agent, Task, Crew, Process
    HAS_CREWAI = True
except ImportError:
    HAS_CREWAI = False


def main():
    print("==================================================")
    print("   AAMARVA ADK - CrewAI Integration Example        ")
    print("==================================================\n")

    # 1. Initialize AAMARVA Client
    client = Aamarva(
        agent_id=os.environ.get("AAMARVA_AGENT_ID", "AMR-CREWAI-DEMO-01"),
        api_key=os.environ.get("AAMARVA_API_KEY", "sk_amr_test_key"),
        base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api"),
    )

    # 2. Authenticate existing agent
    print("1. Authenticating agent and registering P-256 E2EE key...")
    try:
        client.login()
        print("✓ Agent authenticated successfully.")
    except Exception as e:
        print(f"ℹ Agent login note: {e} (proceeding with offline/mock client mode)")

    # 3. Register native CrewAI tools
    print("\n2. Instantiating native AAMARVA CrewAI BaseTools...")
    tools = get_crewai_tools(client)
    print(f"✓ Loaded {len(tools)} AAMARVA CrewAI tools:")
    for t in tools:
        print(f"  - {t.name}: {t.description[:60]}...")

    # Direct tool execution demonstration
    print("\n3. Testing direct CrewAI tool execution...")
    floor_tool = AamarvaFloorTool(client=client)

    # Action 1: List FLOOR tools
    list_res = floor_tool._run(action="list")
    print("\nFLOOR List Result:")
    print(list_res)

    # Action 2: Request access for a tool
    request_res = floor_tool._run(action="request_access", tool_id="tool_sec_edgar", reason="Quarterly filings audit")
    print("\nFLOOR Access Request Result:")
    print(request_res)

    # Action 3: Handle permission denial or execution attempt
    exec_res = floor_tool._run(action="execute", tool_id="tool_unauthorized_admin", arguments={})
    print("\nPermission Denial / Execution Attempt Result:")
    print(exec_res)

    # 4. Form CrewAI Agent & Crew if CrewAI package is installed
    if HAS_CREWAI:
        print("\n4. Attaching AAMARVA tools to CrewAI Agent...")
        agent = Agent(
            role="Fleet Security Auditor",
            goal="Audit AAMARVA FLOOR tool access and verify fleet telemetry.",
            backstory="Autonomous auditor ensuring zero-trust governance across agent fleets.",
            tools=tools,
            verbose=True,
            allow_delegation=False,
        )
        print(f"✓ CrewAI Agent '{agent.role}' created with AAMARVA tools attached.")
    else:
        print("\n4. Note: CrewAI package not installed. Skipping Crew kickoff.")

    print("\n==================================================")
    print("  CrewAI Integration Example Executed Successfully  ")
    print("==================================================")


if __name__ == "__main__":
    main()
