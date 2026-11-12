import jwt

# Never pass options={"verify_signature": False} to jwt.decode.
def claims(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
