from transformers import AutoTokenizer

tok = AutoTokenizer.from_pretrained("./models/bert")
other = AutoTokenizer.from_pretrained(model_dir)
