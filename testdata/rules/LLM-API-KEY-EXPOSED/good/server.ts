import OpenAI from "openai";

export const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
export const mailKey = process.env.PUBLIC_MAIL_KEY;
export const rates = process.env.NEXT_PUBLIC_CHF_KEY;
