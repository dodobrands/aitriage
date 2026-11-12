app.post("/ask", (req, res) => {
  // ruleid: LLM-PROMPT-CONCAT
  const prompt = `Answer the question: ${req.body.question}`;
  res.json({ prompt });
});
