from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/teapot")
def teapot(code: int = 418):
    return HTMLResponse("<h1>Static page</h1>", status_code=code)
