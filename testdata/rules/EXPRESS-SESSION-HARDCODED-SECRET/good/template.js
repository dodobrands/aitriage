const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(session({
  // secret: "keyboard cat" was the old development value
  secret: `${process.env.SESSION_SECRET}`,
  resave: false,
}));
