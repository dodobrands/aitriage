import subprocess


def disk_usage():
    return subprocess.check_output("df -h | sort -k5", shell=True)
