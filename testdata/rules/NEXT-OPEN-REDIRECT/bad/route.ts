import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  // ruleid: NEXT-OPEN-REDIRECT
  return NextResponse.redirect(new URL(req.nextUrl.searchParams.get("next")!));
}
