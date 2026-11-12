import subprocess


def ping(host):
    return subprocess.run(["ping", host], shell=False)
