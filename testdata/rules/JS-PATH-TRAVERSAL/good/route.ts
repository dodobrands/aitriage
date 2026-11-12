import fs from "fs";
import path from "path";

const ROOT = path.resolve(process.cwd(), "uploads");

export async function GET(req: Request) {
  const name = new URL(req.url).searchParams.get("file") ?? "";
  const target = path.resolve(ROOT, path.basename(name));
  if (!target.startsWith(ROOT + path.sep)) return new Response("bad path", { status: 400 });
  return new Response(fs.readFileSync(target));
}
