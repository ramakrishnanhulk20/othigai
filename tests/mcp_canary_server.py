#!/usr/bin/env python3
"""A real stdio MCP server with one harmless tool that logs each call to the file named on the
command line. Runs under the Python environment Hermes uses, which ships the MCP package."""

import sys
from pathlib import Path

from mcp.server import MCPServer

CALL_LOG = Path(sys.argv[1])
server = MCPServer("canary")


@server.tool()
def ping() -> str:
    """Harmless test tool."""
    with CALL_LOG.open("a", encoding="utf-8") as handle:
        handle.write("called\n")
    return "pong"


if __name__ == "__main__":
    server.run("stdio")
