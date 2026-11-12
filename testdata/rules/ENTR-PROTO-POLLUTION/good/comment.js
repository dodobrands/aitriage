// Avoid _.merge(target, req.body): it copies __proto__ keys.
const ALLOWED = ["theme", "locale"];
module.exports = (req, res) => {
  const out = {};
  for (const k of ALLOWED) if (typeof req.body[k] === "string") out[k] = req.body[k];
  res.json(out);
};
