const express = require("express");
const app = express();
app.get("/items/:id", async (req, res) => {
  res.send({ id: req.params.id, item: await repo.get(req.params.id) });
});
