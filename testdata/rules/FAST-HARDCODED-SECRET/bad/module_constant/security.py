import os

ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
# ruleid: FAST-HARDCODED-SECRET
JWT_SECRET = 'not-a-real-jwt-__JOIN__secret-abcdef'
