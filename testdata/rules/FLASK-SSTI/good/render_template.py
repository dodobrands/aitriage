from flask import request, render_template


def page():
    return render_template("page.html", name=request.args.get("name"))
