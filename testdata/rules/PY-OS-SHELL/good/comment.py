import subprocess

# os.system(cmd) was replaced with an argument list.
def ping(host):
    subprocess.run(["ping", "-c", "1", host], check=True)
