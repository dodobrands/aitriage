const express = require("express");
const axios = require("axios");
const app = express();
app.get("/proxy", async (req, res) => {
  // ruleid: EXPRESS-SSRF
  const r = await axios.get(req.query.url);
  res.send(r.data);
});
