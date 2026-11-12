import { NextResponse, type NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const res = NextResponse.next();
  // ruleid: NEXT-CORS
  res.headers.set("Access-Control-Allow-Origin", request.headers.get("origin")!);
  return res;
}
