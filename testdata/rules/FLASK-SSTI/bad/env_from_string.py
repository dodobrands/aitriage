from jinja2 import Environment


def render(user_template):
    # ruleid: FLASK-SSTI
    return Environment().from_string(user_template).render()
