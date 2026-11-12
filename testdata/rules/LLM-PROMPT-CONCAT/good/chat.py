SYSTEM = "You are a helpdesk bot."

def build(request):
    user_prompt = f"Question: {request.json['q']}"
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": request.json["q"]}]
    return messages, user_prompt
