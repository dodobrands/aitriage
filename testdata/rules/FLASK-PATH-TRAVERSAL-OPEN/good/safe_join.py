from flask import abort, request
from werkzeug.utils import safe_join


def read_file():
    path = safe_join("/srv/docs", request.args["name"])
    if path is None:
        abort(404)
    with open(path) as fh:
        return fh.read()
