from subprocess import Popen


def start(cmd):
    # ruleid: PY-SUBPROCESS
    return Popen(cmd, shell=True)
