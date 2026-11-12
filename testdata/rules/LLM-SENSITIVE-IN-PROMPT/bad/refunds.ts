import OpenAI from "openai";

export const messages = [
  // ruleid: LLM-SENSITIVE-IN-PROMPT
  { role: "system", content: `Use API key ${process.env.STRIPE_SECRET_KEY} for refunds` },
];
