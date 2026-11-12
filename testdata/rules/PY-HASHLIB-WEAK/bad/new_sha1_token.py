import hashlib


def sign(token, secret):
    # ruleid: PY-HASHLIB-WEAK
    return hashlib.new("sha1", (token + secret).encode()).hexdigest()
