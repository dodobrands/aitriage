import shutil


def unpack(path, dest):
    shutil.unpack_archive(path, dest, filter="data")
