const express = require("express");
const session = require("express-session");
const app = express();
// ruleid: EXPRESS-SESSION-HARDCODED-SECRET
app.use(session({
  name: "sid",
  secret: process.env.SESSION_SECRET || "dev-__JOIN__secret",
}));
