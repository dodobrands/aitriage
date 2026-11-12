import jwt from "jsonwebtoken";

export function isAdmin(token: string): boolean {
  // ruleid: ENTR-03
  const claims = jwt.decode(token) as { sub: string; role: string } | null;
  return claims?.role === "admin";
}
