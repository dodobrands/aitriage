import cookieParser from "cookie-parser";
import express from "express";
export const app = express();
// ruleid: EXPRESS-SESSION-HARDCODED-SECRET
app.use(cookieParser("cookie-signing-__JOIN__secret"));
