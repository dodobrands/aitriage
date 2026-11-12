from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    # ruleid: PY-BINDING-ALL
    app.run(port=int(get_port()), host="0.0.0.0")
