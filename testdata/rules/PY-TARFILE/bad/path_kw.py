import tarfile


def unpack(path, dest):
    # ruleid: PY-TARFILE
    tar = tarfile.open(path, "r:gz")
    tar.extractall(path=dest)
    tar.close()
