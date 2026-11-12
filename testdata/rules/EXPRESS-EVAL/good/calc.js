const express = require("express");
const { evaluate } = require("mathjs");
const app = express();
app.get("/calc", (req, res) => {
  res.json({ result: evaluate(String(req.query.expr)) });
});
