from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .db import get_db

router = APIRouter()


@router.post("/items")
async def create_item(name: str, db: Session = Depends(get_db)):
    db.add(Item(name=name))
    # ruleid: FAST-SYNC-ASYNC
    db.commit()
    return {"ok": True}
