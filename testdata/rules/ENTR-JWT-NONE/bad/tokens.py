import jwt

def claims(token):
    # ruleid: ENTR-JWT-NONE
    return jwt.decode(token, options={"verify_signature": False})
