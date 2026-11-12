const express = require("express");
const cors = require("cors");
const app = express();
// Public read-only API: any origin, no cookies.
// (cors({ origin: true, credentials: true }) would be unsafe here.)
app.use(cors({ origin: true }));
