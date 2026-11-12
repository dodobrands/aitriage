import tarfile


def unpack(path, dest):
    with tarfile.open(path) as tar:
        tar.extractall(dest, filter="data")
