import tarfile


def unpack(path, dest):
    # ruleid: PY-TARFILE
    with tarfile.open(path) as tar:
        tar.extractall(dest)
