const vm = require("vm");
module.exports = (req, res) => {
  // ruleid: JS-VM-CODE-EXEC
  res.json({ result: vm.runInNewContext(req.body.code, {}) });
};
