import { z } from "zod";
import { User } from "@/models/user";

const Login = z.object({ email: z.string().email(), password: z.string() });

export async function POST(req: Request) {
  const { email } = Login.parse(await req.json());
  const user = await User.findOne({ email: { $eq: email } });
  return Response.json({ ok: Boolean(user) });
}
