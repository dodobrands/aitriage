import jwt

# ruleid: PY-JWT-NOVERIFY
DECODE_OPTIONS = {"verify_signature": False, "verify_exp": True}


def claims(token, key):
    return jwt.decode(token, key, algorithms=["HS256"], options=DECODE_OPTIONS)
