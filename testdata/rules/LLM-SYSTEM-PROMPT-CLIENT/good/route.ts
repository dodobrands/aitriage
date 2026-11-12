import OpenAI from "openai";

const openai = new OpenAI();

export async function POST(req: Request) {
  const systemPrompt = "You are a helpful assistant.";
  return openai.chat.completions.create({ model: "gpt-4o", messages: [{ role: "system", content: systemPrompt }] });
}
