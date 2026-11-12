def build(request):
    # ruleid: LLM-PROMPT-CONCAT
    messages = [{"role": "system", "content": "You are " + request.json["persona"]}]
    return messages
