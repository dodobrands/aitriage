from flask import Flask
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
# WTF_CSRF_ENABLED = False only in the test settings, never here.
CSRFProtect(app)
