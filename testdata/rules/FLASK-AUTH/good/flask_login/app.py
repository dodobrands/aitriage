from flask import Flask
from flask_login import LoginManager, login_required

app = Flask(__name__)
login_manager = LoginManager(app)


@app.route("/profile")
@login_required
def profile():
    return "ok"
