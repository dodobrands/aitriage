from fastapi import FastAPI

# ruleid: FAST-DEBUG
app = FastAPI(
    title="Shop API",
    version="1.0.0",
    debug=True,
)
