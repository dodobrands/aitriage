from flask import Flask

app = Flask(__name__)
# app.run(debug=True)  -- local only
if __name__ == "__main__":
    app.run()
