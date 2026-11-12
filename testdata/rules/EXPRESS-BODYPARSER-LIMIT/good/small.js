const express = require("express");
const bodyParser = require("body-parser");
const app = express();
// express.json({ limit: "50mb" }) was too large; keep it small.
app.use(bodyParser.json({ limit: "100kb" }));
app.post("/import", express.json({ limit: "2mb" }), (req, res) => res.end());
