import OpenAI from "openai";

// ruleid: LLM-API-KEY-EXPOSED
const openai = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });
export default openai;
