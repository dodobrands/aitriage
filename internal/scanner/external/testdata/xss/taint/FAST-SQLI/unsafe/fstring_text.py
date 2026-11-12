from fastapi import APIRouter, Depends
from sqlalchemy import text

router = APIRouter()


@router.get("/users")
def find_users(name: str, session=Depends(get_session)):
    rows = session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
    return [dict(r._mapping) for r in rows]
