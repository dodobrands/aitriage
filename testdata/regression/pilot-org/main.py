import subprocess

from fastapi import FastAPI, Request

app = FastAPI()


@app.get("/ping")
async def ping(host: str):
    # Runs a shell command built from a query parameter.
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.post("/hook")
async def hook(request: Request):
    try:
        payload = await request.json()
        process(payload)
    except Exception:
        pass
    return {"ok": True}


def process(payload):
    return payload
