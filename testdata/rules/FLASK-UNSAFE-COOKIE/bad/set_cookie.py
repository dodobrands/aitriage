from flask import make_response


def login(token):
    resp = make_response("ok")
    # ruleid: FLASK-UNSAFE-COOKIE
    resp.set_cookie("session", token, secure=False, httponly=True)
    return resp
