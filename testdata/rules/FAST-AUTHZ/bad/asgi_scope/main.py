from fastapi import FastAPI
from fastapi.security import HTTPBearer

app = FastAPI()
bearer = HTTPBearer()


class TimingMiddleware:
    """Times each request; it does not check any permission."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        await self.app(scope, receive, send)


@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    USERS.pop(user_id, None)
    return {"deleted": user_id}
