import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")


# ruleid: LLM-TOOL-SHELL-EXEC
@mcp.tool()
def run_command(command: str) -> str:
    """Run a shell command."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout
