from jinja2 import Template


def greet(username):
    # ruleid: FLASK-SSTI
    return Template("Welcome " + username + "!").render()
