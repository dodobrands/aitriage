const jwt = require("jsonwebtoken");

function check(token, key) {
  return jwt.verify(token, key, { algorithms: ["RS256"] });
}
