import os


def configure(app):
    """Load the key from the environment. Do not write:

        app.config["SECRET_KEY"] = "hardcoded-value"
    """
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
