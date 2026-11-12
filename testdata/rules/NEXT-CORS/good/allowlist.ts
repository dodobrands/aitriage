const ALLOWED = new Set(["https://app.example.com"]);

export async function GET(req: Request) {
  const origin = req.headers.get("origin") ?? "";
  const headers: Record<string, string> = {};
  if (ALLOWED.has(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return Response.json({ ok: true }, { headers });
}
