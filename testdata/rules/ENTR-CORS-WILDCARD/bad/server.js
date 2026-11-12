function cors(req, res, next) {
  // ruleid: ENTR-CORS-WILDCARD
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
}
