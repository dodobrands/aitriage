from fastapi import FastAPI

app = FastAPI()


# TODO: protect with OAuth2PasswordBearer
@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    USERS.pop(user_id, None)
    return {"deleted": user_id}
