import jwt from "jsonwebtoken";

export function issue(userId: string) {
  // ruleid: JWT-HARDCODED
  return jwt.sign({ sub: userId }, "super-secret__JOIN__-signing-key", { expiresIn: "1h" });
}
