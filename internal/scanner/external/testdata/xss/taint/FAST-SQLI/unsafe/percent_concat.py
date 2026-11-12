from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/orders")
async def orders(status: str, conn=Depends(get_conn)):
    return await conn.fetch("SELECT * FROM orders WHERE status = '%s'" % status)


@router.get("/products")
def products(sort: str, cur=Depends(get_cursor)):
    cur.execute("SELECT * FROM products ORDER BY " + sort)
    return cur.fetchall()
