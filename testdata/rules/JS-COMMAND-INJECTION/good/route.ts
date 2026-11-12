import { execFile } from "child_process";

export async function POST(req: Request) {
  const { host } = await req.json();
  execFile("ping", ["-c", "1", String(host)], (err, stdout) => console.log(stdout));
  return Response.json({ ok: true });
}
