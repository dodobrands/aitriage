const _ = require("lodash");
module.exports = (req, res) => {
  const config = {};
  // ruleid: ENTR-PROTO-POLLUTION
  _.set(config, req.body.path, req.body.value);
  res.json(config);
};
