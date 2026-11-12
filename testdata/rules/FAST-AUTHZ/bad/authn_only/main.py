from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI()


def require_session(x_session_token: str = Header(...)):
    session = SESSIONS.get(x_session_token)
    if session is None:
        raise HTTPException(status_code=401)
    return session


@app.delete("/users/{user_id}")
def delete_user(user_id: int, session=Depends(require_session)):
    USERS.pop(user_id, None)
    return {"deleted": user_id}
