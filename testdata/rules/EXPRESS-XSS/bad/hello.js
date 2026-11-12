const express = require("express");
const app = express();
app.get("/hello", (req, res) => {
  // ruleid: EXPRESS-XSS
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});
