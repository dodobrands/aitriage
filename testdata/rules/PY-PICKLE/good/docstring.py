import json


def restore(blob):
    """Do not use pickle.loads(blob): it executes code. JSON only."""
    return json.loads(blob)
