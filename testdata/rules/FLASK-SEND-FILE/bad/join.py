import os
from flask import request, send_file


def download():
    # ruleid: FLASK-SEND-FILE
    return send_file(os.path.join("/srv/files", request.args["name"]))
