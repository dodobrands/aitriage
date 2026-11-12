from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
# Reported as FAST-CORS-CREDENTIALS, not twice.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
