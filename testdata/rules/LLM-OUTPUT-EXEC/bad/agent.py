from openai import OpenAI

client = OpenAI()

def run(msgs):
    resp = client.chat.completions.create(model="gpt-4o", messages=msgs)
    # ruleid: LLM-OUTPUT-EXEC
    exec(resp.choices[0].message.content)
