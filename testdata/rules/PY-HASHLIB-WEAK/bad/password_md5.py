import hashlib


def store(user, password):
    # ruleid: PY-HASHLIB-WEAK
    user.password_hash = hashlib.md5(password.encode()).hexdigest()
