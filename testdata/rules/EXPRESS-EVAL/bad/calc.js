const express = require("express");
const app = express();
app.get("/calc", (req, res) => {
  // ruleid: EXPRESS-EVAL
  const result = eval(req.query.expr);
  res.json({ result });
});
