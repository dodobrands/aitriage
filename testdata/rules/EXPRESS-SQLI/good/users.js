const express = require("express");
const router = express.Router();
router.get("/users/:id", async (req, res) => {
  const [rows] = await db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);
  res.json(rows);
});
module.exports = router;
