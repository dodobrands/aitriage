from openai import OpenAI

client = OpenAI()

def summarize(db_password):
    # ruleid: LLM-SENSITIVE-IN-PROMPT
    prompt = f"Log in to the vendor portal with password {db_password} and summarize invoices"
    return client.responses.create(model="gpt-4o", input=prompt)
