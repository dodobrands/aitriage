from html import escape

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/hello")
def hello(name: str):
    return HTMLResponse(f"<h1>{escape(name)}</h1>")
