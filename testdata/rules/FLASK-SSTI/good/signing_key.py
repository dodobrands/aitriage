from ecdsa import SigningKey


def load_key(raw):
    return SigningKey.from_string(raw)
