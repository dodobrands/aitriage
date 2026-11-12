from flask import redirect, request, url_for
from .utils import is_safe_url


def after_login():
    if request.args.get("next") and is_safe_url(request.args.get("next")):
        return redirect(request.args.get("next"))
    return redirect(url_for("index"))
