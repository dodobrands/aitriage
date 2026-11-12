import requests

# Never pass verify=False here.
def fetch(url):
    return requests.get(url, timeout=10)
