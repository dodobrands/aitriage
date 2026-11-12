import subprocess


def run(args):
    subprocess.run(["ls", "-l", args])
