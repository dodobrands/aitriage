from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if request.method == "POST":
        save(request.form)
    return render_template("profile.html")
