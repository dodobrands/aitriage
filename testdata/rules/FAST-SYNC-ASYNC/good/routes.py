from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from .db import get_async_db, get_db

router = APIRouter()


@router.post("/items")
async def create_item(name: str, db: AsyncSession = Depends(get_async_db)):
    db.add(Item(name=name))
    await db.commit()
    return {"ok": True}


@router.post("/legacy-items")
def create_legacy_item(name: str, db: Session = Depends(get_db)):
    db.add(Item(name=name))
    db.commit()
    return {"ok": True}


@router.post("/offloaded-items")
async def create_offloaded_item(name: str, db: Session = Depends(get_db)):
    def save():
        db.add(Item(name=name))
        db.commit()

    await run_in_threadpool(save)
    return {"ok": True}
