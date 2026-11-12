from fastapi import APIRouter, Depends, Request, Response
from fastapi_csrf_protect import CsrfProtect

router = APIRouter()


@router.post("/login")
async def login(request: Request, response: Response, token: str, csrf_protect: CsrfProtect = Depends()):
    await csrf_protect.validate_csrf(request)
    response.set_cookie("session", token, httponly=True, secure=True, samesite="lax")
    return {"ok": True}
