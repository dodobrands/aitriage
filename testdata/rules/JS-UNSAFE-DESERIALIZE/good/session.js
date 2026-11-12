// Replaced require("node-serialize") with JSON.parse.
const NOTE = "node-serialize revives functions";
module.exports = (req, res) => {
  const profile = JSON.parse(Buffer.from(req.cookies.profile, "base64").toString());
  res.json({ name: String(profile.name), note: NOTE });
};
