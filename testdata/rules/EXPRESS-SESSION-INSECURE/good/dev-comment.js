const express = require("express");
const session = require("express-session");
const app = express();
app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    // secure: false only on localhost, see below
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
  },
}));
