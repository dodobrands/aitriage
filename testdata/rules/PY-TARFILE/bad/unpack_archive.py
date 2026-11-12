import shutil


def unpack(path, dest):
    # ruleid: PY-TARFILE
    shutil.unpack_archive(path, dest)
