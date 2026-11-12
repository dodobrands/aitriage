import jwt


def claims(token, key):
    return jwt.decode(token, key, algorithms=["HS256"])
