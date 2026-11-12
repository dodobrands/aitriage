from fastapi import Depends, FastAPI, HTTPException

app = FastAPI()


def require_admin(session=Depends(require_session)):
    if "admin" not in session.roles:
        raise HTTPException(status_code=403)
    return session


@app.delete("/users/{user_id}")
def delete_user(user_id: int, admin=Depends(require_admin)):
    USERS.pop(user_id, None)
    return {"deleted": user_id}
