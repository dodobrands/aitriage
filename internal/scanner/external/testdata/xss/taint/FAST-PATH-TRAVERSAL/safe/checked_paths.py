import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()
UPLOAD_DIR = Path("/srv/uploads").resolve()
BASE_DIR = Path(__file__).parent


def load_config():
    with open(f"{BASE_DIR}/config.yaml") as fh:
        return fh.read()


@router.get("/download/{filename}")
def download(filename: str):
    target = (UPLOAD_DIR / filename).resolve()
    if not target.is_relative_to(UPLOAD_DIR):
        raise HTTPException(status_code=404)
    return FileResponse(target)


@router.get("/avatar/{name}")
def avatar(name: str):
    return FileResponse(os.path.join(UPLOAD_DIR, os.path.basename(name)))


@router.get("/report/{report_id}")
def report(report_id: int):
    return FileResponse(f"{UPLOAD_DIR}/reports/{report_id}.pdf")
