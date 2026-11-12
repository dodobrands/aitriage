const express = require("express");
const router = express.Router();
router.post("/login", async (req, res) => {
  const email = String(req.body.email);
  const user = await User.findOne({ email: { $eq: email } });
  res.json({ ok: Boolean(user) });
});
module.exports = router;
