import tempfile


def scratch():
    fd, path = tempfile.mkstemp(suffix=".txt")
    return fd, path
