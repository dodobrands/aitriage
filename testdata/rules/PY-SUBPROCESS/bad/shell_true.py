import subprocess


def run(cmd):
    # ruleid: PY-SUBPROCESS
    subprocess.run(cmd, shell=True)
