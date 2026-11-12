import fs from "fs";
import path from "path";

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  // ruleid: JS-PATH-TRAVERSAL
  const data = fs.readFileSync(path.join(process.cwd(), "uploads", searchParams.get("file")!));
  return new Response(data);
}
