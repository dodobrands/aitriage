from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

router = APIRouter()


@router.get("/login/done")
def login_done(next: str = "/"):
    return RedirectResponse(next)


@router.get("/logout")
def logout(request: Request):
    return RedirectResponse(url=request.query_params.get("return_to", "/"))
