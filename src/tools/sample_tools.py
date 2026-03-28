"""Sample tools for the MCP Authentication Sample.

This module contains the actual tool implementations. The server.py registers
these tools with FastMCP. This separation allows tools to be tested without
triggering server/auth initialization.
"""


async def hello_world(name: str = "World") -> str:
    """Return a friendly greeting.

    This tool exists solely as a reference implementation showing:
    - How to define a FastMCP tool with typed parameters
    - How to use tags for grouping and filtering
    - The basic structure all tools follow

    Args:
        name: The name to greet. Defaults to "World".
    """
    return f"Hello, {name}!"
