const { execSync } = require("child_process");

function run(completion) {
  // ruleid: LLM-OUTPUT-EXEC
  return execSync(completion.choices[0].message.content);
}
