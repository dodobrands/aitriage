import httpx

# ruleid: PY-REQUESTS-NOVERIFY
client = httpx.Client(verify=False)
