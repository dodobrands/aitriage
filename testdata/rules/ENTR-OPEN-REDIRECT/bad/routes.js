app.get("/go", (req, res) => {
  // ruleid: ENTR-OPEN-REDIRECT
  res.redirect(req.query.next);
});
