from fastapi import APIRouter

router = APIRouter()


@router.post("/login")
def login(username: str, password: str):
    return {"access_token": issue_token(username, password)}
