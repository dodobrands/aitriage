import zipfile


def unpack(path, dest):
    with zipfile.ZipFile(path) as zf:
        zf.extractall(dest)
