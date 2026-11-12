import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text

router = APIRouter()
logger = logging.getLogger(__name__)
SORT_COLUMNS = {"name": "name", "price": "price"}


@router.get("/users")
def find_users(name: str, db=Depends(get_session)):
    rows = db.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})
    logger.info(f"query for {name}")
    return [dict(r._mapping) for r in rows]


@router.get("/orders/{order_id}")
def order(order_id: str, page: int = 1, db=Depends(get_session)):
    query = "SELECT * FROM orders WHERE id = %d" % int(order_id)
    return db.execute(text(query + f" OFFSET {page * 20}")).fetchall()


@router.get("/products")
def products(sort: str, db=Depends(get_session)):
    column = SORT_COLUMNS.get(sort, "name")
    return db.execute(text("SELECT * FROM products ORDER BY " + column)).fetchall()
