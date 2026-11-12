import os
from flask import Flask

app = Flask(__name__)
# ruleid: FLASK-SECRET-HARDCODED
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "fallback-__JOIN__secret-value")
