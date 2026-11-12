import base64
import pickle
from flask import request


def current_prefs():
    # ruleid: FLASK-PICKLE
    return pickle.loads(base64.b64decode(request.cookies.get("prefs", "")))
