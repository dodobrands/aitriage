def build(request):
    # ruleid: LLM-PROMPT-CONCAT
    system_prompt = f"You are a helpdesk bot for {request.args.get('tenant')}"
    return system_prompt
