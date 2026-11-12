const express = require("express");
const session = require("express-session");
const app = express();
// ruleid: EXPRESS-SESSION-HARDCODED-SECRET
app.use(session({ secret: "keyboard __JOIN__cat", resave: false, saveUninitialized: false }));
