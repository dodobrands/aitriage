from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["WTF_CSRF_ENABLED"] = True
CSRFProtect(app)
