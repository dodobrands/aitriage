import { NextResponse } from "next/server";

export function middleware() {
  const nonce = crypto.randomUUID();
  const res = NextResponse.next();
  res.headers.set("Content-Security-Policy", `default-src 'self'; script-src 'self' 'nonce-${nonce}'`);
  return res;
}
