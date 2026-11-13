from fastapi import FastAPI

from app.limits import limiter

app = FastAPI()
app.state.limiter = limiter
