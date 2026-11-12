const express = require("express");
const axios = require("axios");
const app = express();
const ALLOWED = new Set(["api.example.com"]);
app.get("/proxy", async (req, res) => {
  const u = new URL(String(req.query.url));
  if (u.protocol !== "https:" || !ALLOWED.has(u.hostname)) return res.status(400).end();
  const r = await axios.get(u.toString());
  res.send(r.data);
});
