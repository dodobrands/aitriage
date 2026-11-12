from flask import Flask

app = Flask(__name__)
# ruleid: FLASK-UNSAFE-COOKIE
app.config["SESSION_COOKIE_SECURE"] = False
