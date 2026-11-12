const child_process = require("child_process");

function list(dir) {
  // ruleid: JS-COMMAND-INJECTION
  return child_process.execSync("ls -la " + dir).toString();
}
module.exports = { list };
