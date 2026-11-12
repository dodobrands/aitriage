from flask import Flask

app = Flask(__name__)
# ruleid: FLASK-SECRET-HARDCODED
app.config['SECRET_KEY'] = 'dev'
app.config["JWT_SECRET_KEY"] = "dev"
