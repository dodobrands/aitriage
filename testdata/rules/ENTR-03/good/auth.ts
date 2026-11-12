import jwt from "jsonwebtoken";

export function isAdmin(token: string): boolean {
  const claims = jwt.verify(token, process.env.JWT_SECRET as string, {
    algorithms: ["HS256"],
  }) as { sub: string; role: string };
  return claims.role === "admin";
}
