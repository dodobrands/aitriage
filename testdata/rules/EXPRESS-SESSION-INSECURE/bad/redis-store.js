const express = require("express");
const session = require("express-session");
const RedisStore = require("connect-redis").default;
const app = express();
// ruleid: EXPRESS-SESSION-INSECURE
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  cookie: { secure: false },
}));
