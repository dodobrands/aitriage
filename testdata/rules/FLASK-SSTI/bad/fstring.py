from flask import request, render_template_string


def page():
    name = request.args.get("name")
    # ruleid: FLASK-SSTI
    return render_template_string(f"<p>{name}</p>")
