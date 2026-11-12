const express = require("express");
const session = require("express-session");
const app = express();
// ruleid: EXPRESS-SESSION-INSECURE
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  cookie: { httpOnly: true, secure: false },
}));
