def run(program, env):
    # ruleid: PY-EXEC
    try: exec(program, env)
    except Exception:
        pass
