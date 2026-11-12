import ssl


def make_ctx():
    ctx = ssl.create_default_context()
    # ruleid: PY-REQUESTS-NOVERIFY
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
