from jinja2 import Environment, FileSystemLoader

# ruleid: PY-JINJA2-AUTOESCAPE-OFF
env = Environment(loader=FileSystemLoader("templates"))
