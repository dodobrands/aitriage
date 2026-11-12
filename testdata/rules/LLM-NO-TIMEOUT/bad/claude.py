import anthropic

client = anthropic.Anthropic()

def ask(m):
    # ruleid: LLM-NO-TIMEOUT
    return client.messages.create(model="claude-sonnet-4-5", max_tokens=1024, messages=m)
