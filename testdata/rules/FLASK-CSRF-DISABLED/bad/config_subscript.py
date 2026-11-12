from flask import Flask

app = Flask(__name__)
# ruleid: FLASK-CSRF-DISABLED
app.config["WTF_CSRF_ENABLED"] = False
