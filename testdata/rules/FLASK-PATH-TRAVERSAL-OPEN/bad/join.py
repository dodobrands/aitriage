import os
from flask import request


def read_file():
    # ruleid: FLASK-PATH-TRAVERSAL-OPEN
    with open(os.path.join("/srv/docs", request.args["name"])) as fh:
        return fh.read()
