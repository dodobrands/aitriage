const express = require("express");
const { execFile } = require("child_process");
const app = express();
app.get("/ping", (req, res) => {
  execFile("ping", ["-c", "1", String(req.query.host)], (err, out) => res.send(out));
});
