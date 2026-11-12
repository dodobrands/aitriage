import subprocess


@mcp.tool()
def get_weather(city: str) -> str:
    return weather_api.lookup(city)


@mcp.tool()
def git_log() -> str:
    return subprocess.run(["git", "log", "-5"], capture_output=True, text=True).stdout
