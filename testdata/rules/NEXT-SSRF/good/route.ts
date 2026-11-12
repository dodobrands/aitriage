const ALLOWED = new Set(["api.example.com"]);

export async function GET(req: Request) {
  const raw = new URL(req.url).searchParams.get("url") ?? "";
  const target = new URL(raw);
  if (target.protocol !== "https:" || !ALLOWED.has(target.hostname)) {
    return new Response("forbidden", { status: 400 });
  }
  const res = await fetch(target);
  return new Response(await res.text());
}
