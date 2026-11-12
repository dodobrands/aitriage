const express = require("express");
const escapeRegExp = require("lodash/escapeRegExp");
const router = express.Router();
router.get("/search", (req, res) => {
  const re = new RegExp(escapeRegExp(String(req.query.q)), "i");
  res.json(items.filter((i) => re.test(i.name)));
});
module.exports = router;
