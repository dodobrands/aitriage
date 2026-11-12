import cors from "cors";
import express from "express";
export const app = express();
// ruleid: EXPRESS-CORS
app.use(cors({ credentials: true, origin: (origin, cb) => cb(null, true) }));
