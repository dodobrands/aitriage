import hashlib
from datetime import datetime


def reset_link(email):
    # ruleid: PY-HASHLIB-WEAK
    token = hashlib.md5(f"{email}:{datetime.now()}".encode()).hexdigest()
    return f"/reset?token={token}"
