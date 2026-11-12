from openai import OpenAI

client = OpenAI(timeout=30)

def ask(m):
    return client.chat.completions.create(model="o3", messages=m, max_completion_tokens=800)
