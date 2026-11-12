def run(src):
    # ruleid: PY-COMPILE-EXEC
    code = compile(src, "<string>", "exec")
    exec(code)
