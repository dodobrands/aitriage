import { User } from "@/models/user";

export async function POST(req: Request) {
  const body = await req.json();
  // ruleid: NEXT-NOSQL
  const user = await User.findOne({ email: body.email, password: body.password });
  return Response.json({ ok: Boolean(user) });
}
