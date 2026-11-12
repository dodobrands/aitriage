from flask import request


def read_report():
    # ruleid: FLASK-PATH-TRAVERSAL-OPEN
    with open(f"/srv/reports/{request.args.get('id')}.txt") as fh:
        return fh.read()
