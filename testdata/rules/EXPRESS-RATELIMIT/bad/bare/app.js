const express = require("express");
const app = express();
app.disable("x-powered-by");
app.use(express.json());
app.get("/health", (req, res) => res.json({ ok: true }));
app.listen(3000);
