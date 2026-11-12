import json
import os

def handle(tool_call):
    # ruleid: LLM-EXCESSIVE-AGENCY
    os.remove(json.loads(tool_call.function.arguments)["path"])
