import subprocess


def ping(host):
    subprocess.run(["ping", "-c", "1", host], check=True)
