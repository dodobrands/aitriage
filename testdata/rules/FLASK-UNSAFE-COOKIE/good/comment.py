from flask import Flask

app = Flask(__name__)
# SESSION_COOKIE_SECURE = False is only acceptable for local HTTP development.
app.config["SESSION_COOKIE_SECURE"] = True
