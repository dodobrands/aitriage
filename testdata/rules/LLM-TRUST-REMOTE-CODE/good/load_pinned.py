from transformers import AutoModelForCausalLM

model = AutoModelForCausalLM.from_pretrained(name, trust_remote_code=False, revision=MODEL_SHA)
