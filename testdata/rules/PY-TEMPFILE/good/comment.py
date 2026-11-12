import tempfile

# tempfile.mktemp() is racy; NamedTemporaryFile is used instead.
def scratch():
    return tempfile.NamedTemporaryFile(delete=False)
