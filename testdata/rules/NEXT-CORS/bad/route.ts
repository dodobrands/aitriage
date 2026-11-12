export async function GET(req: Request) {
  return Response.json({ ok: true }, {
    headers: {
      // ruleid: NEXT-CORS
      "Access-Control-Allow-Origin": req.headers.get("origin") ?? "*",
      "Access-Control-Allow-Credentials": "true",
    },
  });
}
