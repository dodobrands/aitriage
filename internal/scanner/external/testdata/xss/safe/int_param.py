from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI()


@app.get("/tasks/{task_id}")
def task(task_id: int, page: int = 1):
    return HTMLResponse(f"<p>Task {task_id}, page {page}</p>")
