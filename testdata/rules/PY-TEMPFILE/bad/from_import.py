# ruleid: PY-TEMPFILE
from tempfile import mktemp


def scratch():
    return open(mktemp(), "w")
