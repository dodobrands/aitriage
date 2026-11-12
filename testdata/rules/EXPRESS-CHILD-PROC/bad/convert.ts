import express from "express";
import child_process from "child_process";
export const app = express();
app.post("/convert", (req, res) => {
  // ruleid: EXPRESS-CHILD-PROC
  child_process.execSync(`convert ${req.body.file} out.png`);
  res.end();
});
