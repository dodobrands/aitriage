import hashlib


def doc_fingerprint(tokens):
    return hashlib.md5(" ".join(tokens).encode()).hexdigest()  # content id for tokens
