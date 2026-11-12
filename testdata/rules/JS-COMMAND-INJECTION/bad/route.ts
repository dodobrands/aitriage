import { exec } from "child_process";

export async function POST(req: Request) {
  const { host } = await req.json();
  // ruleid: JS-COMMAND-INJECTION
  exec(`ping -c 1 ${host}`, (err, stdout) => console.log(stdout));
  return Response.json({ ok: true });
}
