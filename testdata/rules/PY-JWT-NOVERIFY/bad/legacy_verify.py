import jwt


def claims(token):
    # ruleid: PY-JWT-NOVERIFY
    return jwt.decode(token, verify=False)
