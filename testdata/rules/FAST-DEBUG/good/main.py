import os

from fastapi import FastAPI

# FastAPI(debug=True) would return tracebacks to clients.
app = FastAPI(title="Shop API", debug=os.environ.get("APP_DEBUG") == "1")
