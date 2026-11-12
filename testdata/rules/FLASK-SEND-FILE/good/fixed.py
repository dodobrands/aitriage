from flask import send_file


def report():
    return send_file("/srv/reports/latest.pdf")
