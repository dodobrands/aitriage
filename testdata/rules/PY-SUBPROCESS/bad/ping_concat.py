import subprocess


def ping(host):
    # ruleid: PY-SUBPROCESS
    return subprocess.check_output("ping -c 1 " + host, shell=True)
