from openai import OpenAI

client = OpenAI(timeout=30)

def chat(m):
    # ruleid: LLM-NO-TOKEN-LIMIT
    return client.chat.completions.create(model="gpt-4o", messages=m)
