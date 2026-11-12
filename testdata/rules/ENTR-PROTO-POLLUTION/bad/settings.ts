import merge from "lodash/merge";

export async function POST(req: Request) {
  const settings = {};
  // ruleid: ENTR-PROTO-POLLUTION
  merge(settings, await req.json());
  return Response.json(settings);
}
