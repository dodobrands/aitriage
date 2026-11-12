import ast
import subprocess

def parse(raw_output):
    tool_output = ast.literal_eval(raw_output)
    result = subprocess.run(["git", "status"], capture_output=True)
    output = result.stdout
    return tool_output, output
