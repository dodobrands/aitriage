from fastapi import Depends, FastAPI
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI()
bearer = HTTPBearer()


@app.delete("/users/{user_id}")
def delete_user(user_id: int, creds: HTTPAuthorizationCredentials = Depends(bearer)):
    USERS.pop(user_id, None)
    return {"deleted": user_id}
