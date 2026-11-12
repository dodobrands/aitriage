import functools

import httpx
from fastapi.responses import HTMLResponse


@functools.lru_cache(maxsize=32)
def banner(title: str):
    return HTMLResponse(f"<h1>{title}</h1>")


async def proxy_page(client: httpx.AsyncClient):
    resp = await client.get("https://status.example.com/")
    return HTMLResponse(f"<p>{resp.headers.get('server')}</p>")
