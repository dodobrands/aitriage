from flask import request


def restore():
    return request.get_json()
