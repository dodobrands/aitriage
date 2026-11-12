const { evaluate } = require("mathjs");
// vm.runInNewContext(code) is not a sandbox, so it is not used here.
module.exports = (req, res) => {
  res.json({ result: evaluate(String(req.body.expr)) });
};
