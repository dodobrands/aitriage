import csv

from fastapi import APIRouter, UploadFile

router = APIRouter()


@router.post("/import")
async def import_rows(file: UploadFile):
    text = (await file.read()).decode()
    rows = list(csv.reader(text.splitlines(), delimiter=";"))
    return {"rows": len(rows)}
