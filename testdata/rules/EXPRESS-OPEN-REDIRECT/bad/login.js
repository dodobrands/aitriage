const express = require("express");
const app = express();
app.get("/login/callback", (req, res) => {
  // ruleid: EXPRESS-OPEN-REDIRECT
  res.redirect(req.query.next);
});
