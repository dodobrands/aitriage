import express from "express";
export const app = express();
app.get("/go", (req, res) => {
  // ruleid: EXPRESS-OPEN-REDIRECT
  res.redirect(302, req.query.url as string);
});
