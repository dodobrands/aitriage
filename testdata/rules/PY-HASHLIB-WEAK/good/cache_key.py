import hashlib
import json


def cache_key(params):
    return hashlib.sha1(json.dumps(params, sort_keys=True).encode()).hexdigest()


def checksum(data):
    return hashlib.md5(data, usedforsecurity=False).hexdigest()
