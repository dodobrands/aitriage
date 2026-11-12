const express = require("express");
const app = express();
app.get("/login/callback", (req, res) => {
  const next = String(req.query.next || "/");
  res.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");
});
