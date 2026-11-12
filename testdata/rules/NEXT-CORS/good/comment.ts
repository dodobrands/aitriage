// Do not write "Access-Control-Allow-Origin": req.headers.get("origin") here;
// this endpoint is same-origin only.
export async function POST(req: Request) {
  return Response.json(await req.json());
}
