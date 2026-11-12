def first_headers_without_set_cookie(headers):
    # Strips response.set_cookie() output before caching.
    return [(k, v) for k, v in headers if k.lower() != "set-cookie"]
