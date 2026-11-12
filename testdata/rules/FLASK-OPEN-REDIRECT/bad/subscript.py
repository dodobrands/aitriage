from flask import redirect, request


def go():
    # ruleid: FLASK-OPEN-REDIRECT
    return redirect(request.args["url"])
