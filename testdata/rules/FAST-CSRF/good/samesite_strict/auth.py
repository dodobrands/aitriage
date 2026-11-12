from fastapi import APIRouter, Response

router = APIRouter()


@router.post("/login")
def login(response: Response, token: str):
    response.set_cookie("session", token, httponly=True, secure=True, samesite="strict")
    return {"ok": True}
