from flask import Flask
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app)

if __name__ == "__main__":
    # ruleid: FLASK-DEBUG
    socketio.run(app, debug=True)
