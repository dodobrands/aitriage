from jose import jwt


def user_id(token):
    # ruleid: PY-JWT-NOVERIFY
    return jwt.get_unverified_claims(token)["sub"]
