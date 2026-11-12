from openai import OpenAI

client = OpenAI(timeout=30)

def summarize(m):
    return client.chat.completions.create(model="gpt-4o", messages=m)
