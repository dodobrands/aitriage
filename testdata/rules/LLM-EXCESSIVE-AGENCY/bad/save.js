const fs = require("fs");

function save(llmPath, completion) {
  // ruleid: LLM-EXCESSIVE-AGENCY
  fs.writeFileSync(llmPath, completion.choices[0].message.content);
}
