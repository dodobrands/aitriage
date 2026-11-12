import jwt


def claims(token):
    # ruleid: PY-JWT-NOVERIFY
    return jwt.decode(token, options={"verify_signature": False})
