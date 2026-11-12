from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

app = FastAPI()
env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape())


def render(name, **context):
    return env.get_template(name).render(**context)


@app.get("/picker", response_class=HTMLResponse)
def picker(q: str = ""):
    return render("picker.html", q=q)


@app.get("/picker2")
def picker2(q: str = ""):
    return HTMLResponse(env.get_template("picker.html").render(q=q))
