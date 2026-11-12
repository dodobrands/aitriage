import json

def plan(completion):
    # ruleid: LLM-NO-OUTPUT-VALIDATION
    data = json.loads(completion.choices[0].message.content)
    return data["steps"]
