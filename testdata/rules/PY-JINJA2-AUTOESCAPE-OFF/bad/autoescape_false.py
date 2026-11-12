import jinja2

# ruleid: PY-JINJA2-AUTOESCAPE-OFF
env = jinja2.Environment(loader=jinja2.FileSystemLoader("t"), autoescape=False)
