from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    # ruleid: FAST-CORS-CREDENTIALS
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
)
