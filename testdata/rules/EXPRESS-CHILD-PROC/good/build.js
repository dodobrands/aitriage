const { execSync } = require("child_process");
const BRANCH = "main";
// exec("git log " + req.query.ref) would be unsafe; the branch here is a constant.
const sha = execSync(`git rev-parse ${BRANCH}`).toString().trim();
module.exports = { sha };
