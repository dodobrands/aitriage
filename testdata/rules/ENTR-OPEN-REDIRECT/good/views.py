from flask import redirect, url_for

def profile(params):
    return redirect(url_for("profile", user_id=params.user_id))
