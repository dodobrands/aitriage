import cookieSession from "cookie-session";
import express from "express";
export const app = express();
// ruleid: EXPRESS-SESSION-INSECURE
app.use(cookieSession({ secure: false, name: "session", keys: [process.env.COOKIE_KEY!] }));
