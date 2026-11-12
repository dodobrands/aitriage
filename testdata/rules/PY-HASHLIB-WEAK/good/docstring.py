import hashlib


def file_etag(data):
    """Do not reuse this for secrets: hashlib.md5(password) is not a password hash."""
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
