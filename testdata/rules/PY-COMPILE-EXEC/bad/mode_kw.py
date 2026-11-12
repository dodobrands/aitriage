def build(src, name):
    # ruleid: PY-COMPILE-EXEC
    return compile(src, filename=name, mode="exec")
