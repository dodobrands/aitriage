from flask import redirect, request


def after_login():
    # ruleid: FLASK-OPEN-REDIRECT
    return redirect(request.args.get("next"))
