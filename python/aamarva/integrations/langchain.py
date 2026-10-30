"""
LangChain Integration for AAMARVA ADK (Python)

Provides LangChain-compatible tools exposing AAMARVA sovereign fleet capabilities
and FLOOR governance.
"""

import json
from typing import Optional, Dict, Any, List, Callable
from .openai import execute_openai_tool_call, get_openai_tools

try:
    from langchain_core.tools import BaseTool, StructuredTool
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseTool = object
    StructuredTool = None


class AamarvaLangChainTool:
    """
    Duck-typed LangChain tool supporting invoke, run, _run, and JSON Schema.
    """
    def __init__(self, name: str, description: str, schema: Dict[str, Any], handler: Callable[[Any], Any]):
        self.name = name
        self.description = description
        self.args_schema = schema
        self.handler = handler

    def invoke(self, input_data: Any) -> str:
        return self.run(input_data)

    def run(self, *args, **kwargs) -> str:
        input_data = {}
        if args:
            if len(args) == 1 and isinstance(args[0], dict):
                input_data = args[0]
            elif len(args) == 1 and isinstance(args[0], str):
                try:
                    input_data = json.loads(args[0])
                except Exception:
                    input_data = {"input": args[0]}
        if kwargs:
            input_data.update(kwargs)

        try:
            res = self.handler(input_data)
            if isinstance(res, (dict, list)):
                return json.dumps(res, default=str)
            return str(res)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def _run(self, *args, **kwargs) -> str:
        return self.run(*args, **kwargs)

    async def _arun(self, *args, **kwargs) -> str:
        return self.run(*args, **kwargs)


def get_langchain_tools(client: Optional[Any] = None) -> List[Any]:
    if client is None:
        from ..client import Aamarva
        client = Aamarva()

    openai_tools = get_openai_tools(client)
    tools = []

    for item in openai_tools:
        fn = item["function"]
        name = fn["name"]
        description = fn["description"]
        schema = fn["parameters"]

        def make_handler(tool_name: str):
            return lambda args: execute_openai_tool_call(client, tool_name, args)

        handler = make_handler(name)
        tool = AamarvaLangChainTool(
            name=name,
            description=description,
            schema=schema,
            handler=handler,
        )
        tools.append(tool)

    return tools


def execute_langchain_tool(client: Any, name: str, input_args: Any) -> str:
    tools = get_langchain_tools(client)
    tool = next((t for t in tools if t.name == name), None)
    if not tool:
        raise ValueError(f"LangChain tool not found: {name}")
    return tool.invoke(input_args)
