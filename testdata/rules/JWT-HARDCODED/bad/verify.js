const jwt = require("jsonwebtoken");

function check(token) {
  // ruleid: JWT-HARDCODED
  return jwt.verify(token, "super-secret__JOIN__-signing-key");
}
module.exports = { check };
