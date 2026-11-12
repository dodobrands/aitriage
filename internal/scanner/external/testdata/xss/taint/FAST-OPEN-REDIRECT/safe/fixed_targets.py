from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

router = APIRouter()
TARGETS = {"home": "/", "orders": "/orders"}


@router.get("/login/done")
def login_done(request: Request):
    return RedirectResponse(request.url_for("dashboard"))


@router.get("/go")
def go(target: str):
    return RedirectResponse(TARGETS.get(target, "/"))


@router.get("/continue")
def continue_to(next: str = "/"):
    if not is_safe_redirect(next):
        raise HTTPException(status_code=400)
    return RedirectResponse(next)
