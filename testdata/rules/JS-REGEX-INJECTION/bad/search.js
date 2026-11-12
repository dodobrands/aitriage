const express = require("express");
const router = express.Router();
router.get("/search", (req, res) => {
  // ruleid: JS-REGEX-INJECTION
  const re = new RegExp(req.query.q, "i");
  res.json(items.filter((i) => re.test(i.name)));
});
module.exports = router;
