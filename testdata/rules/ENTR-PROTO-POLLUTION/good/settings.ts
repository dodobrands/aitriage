import { z } from "zod";

const Settings = z.object({ theme: z.enum(["light", "dark"]) }).strict();

export async function POST(req: Request) {
  const settings = Settings.parse(await req.json());
  return Response.json(settings);
}
