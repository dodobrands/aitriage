const express = require("express");
const router = express.Router();
// Never call User.findOne(req.body): it accepts {"$ne": null}.
router.get("/users/:id", async (req, res) => {
  res.json(await User.findById(String(req.params.id)));
});
module.exports = router;
