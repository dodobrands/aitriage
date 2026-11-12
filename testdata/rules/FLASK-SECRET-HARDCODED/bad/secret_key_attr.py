from flask import Flask

app = Flask(__name__)
# ruleid: FLASK-SECRET-HARDCODED
app.secret_key = "s3cr3t-__JOIN__k3y-value"
