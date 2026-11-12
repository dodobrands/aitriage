export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  // ruleid: NEXT-SSRF
  const res = await fetch(searchParams.get("url")!);
  return new Response(await res.text());
}
