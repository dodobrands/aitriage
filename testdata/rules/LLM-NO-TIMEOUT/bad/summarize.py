from openai import OpenAI

client = OpenAI()

def summarize(m):
    # ruleid: LLM-NO-TIMEOUT
    return client.chat.completions.create(model="gpt-4o", messages=m, max_completion_tokens=500)
