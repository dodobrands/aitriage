export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  // ruleid: JS-REGEX-INJECTION
  const re = new RegExp(searchParams.get("q") ?? "");
  return Response.json(["a", "b"].filter((s) => re.test(s)));
}
