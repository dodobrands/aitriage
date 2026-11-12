from fastapi import APIRouter, Response

router = APIRouter()


@router.post("/login")
def login(response: Response, token: str):
    # ruleid: FAST-CSRF
    response.set_cookie("session", token, httponly=True, secure=True)
    return {"ok": True}
