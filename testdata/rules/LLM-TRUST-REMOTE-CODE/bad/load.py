from transformers import AutoModelForCausalLM

# ruleid: LLM-TRUST-REMOTE-CODE
model = AutoModelForCausalLM.from_pretrained(name, trust_remote_code=True)
