import os


def ping(host):
    # ruleid: PY-OS-SHELL
    return os.system("ping -c 1 " + host)
