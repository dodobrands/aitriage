from flask import redirect, request


def back():
    # ruleid: FLASK-OPEN-REDIRECT
    return redirect(request.referrer)
