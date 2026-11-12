import subprocess


def archive(name):
    # ruleid: PY-SUBPROCESS
    subprocess.run(
        f"tar czf /tmp/{name}.tgz /data/{name}",
        shell=True,
        check=True,
    )
