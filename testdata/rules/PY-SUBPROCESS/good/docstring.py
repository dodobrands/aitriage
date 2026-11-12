import subprocess


def ping(host):
    """Never call subprocess.run(cmd, shell=True) with user input."""
    return subprocess.run(["ping", "-c", "1", host], check=True)
