const mathjs = require("mathjs");

function calc(req, res) {
  // ruleid: EXPRESS-EVAL
  res.json({ output: mathjs.eval(req.body.eqn) });
}

module.exports = { calc };
