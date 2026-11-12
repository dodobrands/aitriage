app.get("/preview", async (req, res) => {
  // ruleid: ENTR-SSRF
  const r = await fetch(req.query.url);
  res.send(await r.text());
});
