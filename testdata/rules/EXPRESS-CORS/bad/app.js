const express = require("express");
const cors = require("cors");
const app = express();
// ruleid: EXPRESS-CORS
app.use(cors({ origin: true, credentials: true }));
