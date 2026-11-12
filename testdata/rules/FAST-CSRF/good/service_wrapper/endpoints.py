from fastapi import APIRouter, Request, Response

router = APIRouter()


@router.post("/login/callback")
async def callback(request: Request, response: Response, code: str):
    session = await session_service.create(code)
    await session_service.set_cookie(request, response, session)
    return {"ok": True}
