const fs = require("fs");
module.exports = function handler(req, res) {
  // ruleid: JS-PATH-TRAVERSAL
  fs.readFile(`./public/${req.query.file}`, (err, data) => res.end(data));
};
