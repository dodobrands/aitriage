import httpx
import requests
from fastapi import APIRouter

router = APIRouter()


@router.get("/preview")
async def preview(url: str):
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
    return {"status": resp.status_code}


@router.post("/webhook-test")
def webhook_test(target: str):
    return {"status": requests.post(target, json={"ping": True}, timeout=5).status_code}
