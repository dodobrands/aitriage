from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/search", response_class=HTMLResponse)
def search(request: Request, q: str = ""):
    return templates.TemplateResponse(request, "search.html", {"q": q})
