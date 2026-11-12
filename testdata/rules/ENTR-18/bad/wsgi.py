from werkzeug.serving import run_simple

from app import application

if __name__ == "__main__":
    # ruleid: ENTR-18
    run_simple("127.0.0.1", 5000, application,
               use_debugger=True, use_reloader=True)
