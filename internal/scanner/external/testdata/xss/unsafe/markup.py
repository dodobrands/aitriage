from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/bio")
def bio(request: Request, text: str):
    bio_html = Markup(f"<p>{text}</p>")
    return templates.TemplateResponse(request, "bio.html", {"bio": bio_html})
