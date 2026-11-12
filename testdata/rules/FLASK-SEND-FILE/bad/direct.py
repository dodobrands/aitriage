from flask import request, send_file


def download():
    # ruleid: FLASK-SEND-FILE
    return send_file(request.args.get("path"))
