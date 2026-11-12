import subprocess


def run_tool(args):
    # ruleid: PY-SUBPROCESS
    subprocess.call(" ".join(args), cwd=get_dir(), shell=True)
