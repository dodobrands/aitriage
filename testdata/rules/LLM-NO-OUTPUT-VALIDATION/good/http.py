import json

def read(response, progress):
    response_data = json.loads(response.content)
    evidence = json.loads(progress.completion_evidence)
    return response_data, evidence
