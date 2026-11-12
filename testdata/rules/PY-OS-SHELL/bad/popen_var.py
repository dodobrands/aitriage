import os


def run(cmd):
    # ruleid: PY-OS-SHELL
    return os.popen(cmd).read()
