import os

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()
UPLOAD_DIR = "/srv/uploads"


@router.get("/download/{filename}")
def download(filename: str):
    return FileResponse(os.path.join(UPLOAD_DIR, filename))


@router.get("/raw/{filename}")
def raw(filename: str):
    with open(UPLOAD_DIR + "/" + filename, "rb") as fh:
        return fh.read()


@router.delete("/files")
def delete_file(path: str):
    os.remove(f"{UPLOAD_DIR}/{path}")
    return {"deleted": path}
