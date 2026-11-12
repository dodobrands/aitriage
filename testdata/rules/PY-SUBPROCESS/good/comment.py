import subprocess

# Do not use subprocess.run(cmd, shell=True) here: it enables command injection.
def ping(host):
    return subprocess.run(["ping", "-c", "1", host], check=True)
