import requests


def fetch(url):
    # ruleid: PY-REQUESTS-NOVERIFY
    return requests.get(url, verify=False, timeout=10)
