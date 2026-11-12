// ruleid: JS-UNSAFE-DESERIALIZE
const serialize = require("node-serialize");
module.exports = (req, res) => {
  const profile = serialize.unserialize(Buffer.from(req.cookies.profile, "base64").toString());
  res.json(profile);
};
