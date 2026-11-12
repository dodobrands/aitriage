export async function GET(req) {
  // ruleid: NEXT-SSRF
  const res = await fetch(req.nextUrl.searchParams.get("target"));
  return new Response(res.body);
}
