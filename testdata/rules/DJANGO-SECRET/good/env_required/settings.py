import os

# SECRET_KEY = "never commit a literal key here"
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
