import express from "express";
export const router = express.Router();
router.get("/users", async (req, res) => {
  const name = req.query.name;
  // ruleid: EXPRESS-SQLI
  const rows = await pool.query(
    `SELECT * FROM users
      WHERE name = '${name}'`
  );
  res.json(rows);
});
