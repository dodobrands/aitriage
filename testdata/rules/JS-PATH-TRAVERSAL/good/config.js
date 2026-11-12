const fs = require("fs");
// fs.readFile(req.query.file) would let callers read any file; read a fixed one.
fs.readFile(`./config.json`, "utf8", (err, data) => console.log(data));
