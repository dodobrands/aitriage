import express from "express";
export const router = express.Router();
router.post("/login", async (req, res) => {
  // ruleid: EXPRESS-NOSQL
  const user = await User.findOne({ email: req.body.email, password: req.body.password });
  res.json({ ok: Boolean(user) });
});
