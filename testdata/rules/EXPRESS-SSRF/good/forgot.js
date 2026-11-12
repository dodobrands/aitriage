const express = require("express");
const router = express.Router();
router.post("/forgot", async (req, res) => {
  await authService.forgot(req.body.email);
  res.status(204).end();
});
module.exports = router;
