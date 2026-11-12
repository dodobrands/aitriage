from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
# ruleid: FAST-CORS-WILDCARD
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=["*"])
