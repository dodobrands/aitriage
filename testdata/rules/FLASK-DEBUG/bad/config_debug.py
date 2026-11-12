from flask import Flask

app = Flask(__name__)
# ruleid: FLASK-DEBUG
app.config["DEBUG"] = True
