import requests


def fetch(url, ca_bundle):
    return requests.get(url, verify=ca_bundle, timeout=10)
