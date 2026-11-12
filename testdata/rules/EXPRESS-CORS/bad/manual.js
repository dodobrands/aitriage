const express = require("express");
const app = express();
app.use((req, res, next) => {
  // ruleid: EXPRESS-CORS
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});
