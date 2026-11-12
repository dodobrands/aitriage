import requests

CLIENT_SECRET = "f9Kd82LmQz7Xp3Vn6Rt1Yw4Bc8Hj5Ns2"


def token():
    return requests.post("https://auth.example.com/token", data={"secret": CLIENT_SECRET}, timeout=5)
