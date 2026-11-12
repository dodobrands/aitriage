"use client";

export function Debug() {
  // ruleid: ENTR-09
  return <pre>{process.env.NEXTAUTH_SECRET}</pre>;
}
