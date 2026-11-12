const crypto = require("crypto");

function hashPassword(password) {
  // ruleid: ENTR-WEAK-CRYPTO
  return crypto.createHash("md5").update(password).digest("hex");
}
