from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.post("/comment")
async def comment(request: Request):
    form = await request.form()
    return HTMLResponse(f"<p>{form['body']}</p>")


@app.get("/whoami")
async def whoami(request: Request):
    return HTMLResponse("<p>" + request.cookies.get("display_name", "") + "</p>")


@app.get("/ua")
async def ua(request: Request):
    return HTMLResponse(f"<p>{request.headers.get('user-agent')}</p>")
