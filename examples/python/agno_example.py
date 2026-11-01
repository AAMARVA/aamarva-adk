"""
AAMARVA ADK - Agno Integration Example

Demonstrates how to attach the native AAMARVA Agno Toolkit to an existing Agno agent
without modifying agent reasoning or LLM architecture.
"""

import os
import json
from aamarva import Aamarva
from aamarva.integrations.agno import AamarvaAgnoToolkit

try:
    from agno.agent import Agent
    HAS_AGNO = True
except ImportError:
    HAS_AGNO = False


def main():
    print("==================================================")
    print("   AAMARVA ADK - Agno Integration Example          ")
    print("==================================================\n")

    # 1. Initialize AAMARVA Client
    client = Aamarva(
        agent_id=os.environ.get("AAMARVA_AGENT_ID", "AMR-AGNO-DEMO-01"),
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

    # 3. Register native Agno Toolkit
    print("\n2. Instantiating AAMARVA Agno Toolkit...")
    try:
        toolkit = AamarvaAgnoToolkit(client=client)
        print("✓ AamarvaAgnoToolkit initialized with registered fleet tools.")

        # Test capability call 1: FLOOR list tools
        print("\n3. Invoking aamarva_floor_list_tools()...")
        floor_tools_str = toolkit.aamarva_floor_list_tools()
        print("FLOOR Tools Response:")
        print(floor_tools_str)

        # Test capability call 2: Request FLOOR access
        print("\n4. Invoking aamarva_floor_request_access()...")
        req_str = toolkit.aamarva_floor_request_access("tool_sec_edgar", "Financial audit")
        print("Access Request Response:")
        print(req_str)

        # Test capability call 3: Handle permission denial
        print("\n5. Invoking aamarva_floor_execute_tool() for unauthorized tool...")
        denied_str = toolkit.aamarva_floor_execute_tool("tool_unauthorized_admin", {})
        print("Permission Denial Response:")
        print(denied_str)

    except ImportError as e:
        print(f"ℹ Agno package dependency note: {e}")

    # 4. Attach to Agno Agent if Agno is installed
    if HAS_AGNO:
        print("\n6. Attaching AamarvaAgnoToolkit to Agno Agent...")
        agent = Agent(
            name="AAMARVA Fleet Manager",
            tools=[toolkit],
            instructions=["Manage machine-to-machine operations using AAMARVA ADK tools."],
            show_tool_calls=True,
        )
        print(f"✓ Agno Agent '{agent.name}' initialized with AAMARVA Toolkit.")
    else:
        print("\n6. Note: Agno package not installed. Skipping Agno Agent creation.")

    print("\n==================================================")
    print("   Agno Integration Example Executed Successfully  ")
    print("==================================================")


if __name__ == "__main__":
    main()
