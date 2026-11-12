from flask import Flask

app = Flask(__name__)

if __name__ == "__main__":
    # ruleid: FLASK-DEBUG
    app.run(host=get_host(), debug=True)
