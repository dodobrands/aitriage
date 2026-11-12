from flask import render_template_string


def page(items):
    return render_template_string("""
    <ul>{% for i in items %}<li>{{ i }}</li>{% endfor %}</ul>
    """, items=items)
