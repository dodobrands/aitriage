const express = require("express");
const session = require("express-session");
const app = express();
if (!process.env.SESSION_SECRET) throw new Error("SESSION_SECRET is required");
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
