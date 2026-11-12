const express = require("express");
const router = express.Router();
router.post("/login", async (req, res) => {
  // ruleid: EXPRESS-NOSQL
  const user = await User.findOne(req.body);
  res.json({ ok: Boolean(user) });
});
module.exports = router;
