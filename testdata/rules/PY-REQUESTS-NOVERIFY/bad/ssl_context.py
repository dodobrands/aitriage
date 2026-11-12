import ssl
import urllib.request


def fetch(url):
    # ruleid: PY-REQUESTS-NOVERIFY
    ctx = ssl._create_unverified_context()
    return urllib.request.urlopen(url, context=ctx)
