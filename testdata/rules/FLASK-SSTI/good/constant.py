from flask import request, render_template_string


def page():
    return render_template_string("<p>{{ name }}</p>", name=request.args.get("name"))
