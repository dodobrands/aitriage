import express from "express";
const app = express();
app.get("/proxy", async (req, res) => {
  // ruleid: EXPRESS-SSRF
  const r = await fetch(req.query.url);
  res.send(await r.text());
});
