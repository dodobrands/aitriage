from fastapi import APIRouter, Depends, Request
from sqlalchemy import text

router = APIRouter()


@router.post("/orders/{order_id}/status")
async def set_status(order_id: int, request: Request, db=Depends(get_db)):
    body = await request.json()
    raw_sql = f"""
        UPDATE orders
        SET status = '{body["status"]}'
        WHERE id = {order_id}
    """
    await db.execute(text(raw_sql))
    return {"ok": True}
