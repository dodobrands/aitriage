from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException

router = APIRouter()
ALLOWED_HOSTS = {"api.partner.example"}
SESSIONS = {}


@router.get("/preview")
def preview(url: str):
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400)
    return {"status": requests.get(url, timeout=5).status_code}


@router.get("/session")
def session_info(token: str):
    session = SESSIONS.get(token)
    return {"active": session is not None}


@router.get("/partner/{item_id}")
def partner_item(item_id: int):
    return requests.get(f"https://api.partner.example/items/{item_id}", timeout=5).json()
