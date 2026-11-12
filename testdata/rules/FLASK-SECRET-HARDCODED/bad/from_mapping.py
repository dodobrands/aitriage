from flask import Flask


def create_app():
    app = Flask(__name__)
    # ruleid: FLASK-SECRET-HARDCODED
    app.config.from_mapping(SECRET_KEY="dev", DATABASE="app.sqlite")
    return app
