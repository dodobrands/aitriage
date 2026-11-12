from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


# ruleid: FLASK-CSRF-DISABLED
@csrf.exempt
def transfer():
    return "ok"
