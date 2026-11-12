const jwt = require("jsonwebtoken");

function check(token, key) {
  // ruleid: ENTR-JWT-NONE
  return jwt.verify(token, key, { algorithms: ["HS256", "none"] });
}
