const express = require("express");
const app = express();
app.get("/search", (req, res) => {
  // ruleid: EXPRESS-XSS
  res.send(req.query.q);
});
