from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/hello")
def hello():
    template = "<h1>Hello %s</h1>" % request.args.get("name", "")
    # ruleid: FLASK-SSTI
    return render_template_string(template)
