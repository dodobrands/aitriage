import jwt


def claims(token, keys):
    kid = jwt.get_unverified_header(token)["kid"]
    return jwt.decode(token, keys[kid], algorithms=["RS256"])
