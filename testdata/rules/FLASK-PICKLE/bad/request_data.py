import pickle
from flask import Flask, request

app = Flask(__name__)


@app.route("/restore", methods=["POST"])
def restore():
    # ruleid: FLASK-PICKLE
    obj = pickle.loads(request.get_data())
    return str(obj)
