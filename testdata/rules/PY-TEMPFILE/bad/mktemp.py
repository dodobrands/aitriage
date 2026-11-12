import tempfile


def scratch():
    # ruleid: PY-TEMPFILE
    path = tempfile.mktemp(suffix=".txt")
    return open(path, "w")
