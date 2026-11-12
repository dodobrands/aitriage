import os
from flask import Flask

app = Flask(__name__)
# Never write: app.secret_key = "hardcoded-value"
app.secret_key = os.environ["SECRET_KEY"]
