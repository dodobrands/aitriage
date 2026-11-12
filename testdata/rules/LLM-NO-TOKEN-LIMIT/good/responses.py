from openai import OpenAI

client = OpenAI(timeout=30)

def ask(m):
    return client.responses.create(model="gpt-4o", input=m, max_output_tokens=800)
