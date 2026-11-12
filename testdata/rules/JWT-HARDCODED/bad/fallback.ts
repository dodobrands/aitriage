import jwt from "jsonwebtoken";

export function issue(userId: string) {
  // ruleid: JWT-HARDCODED
  return jwt.sign({ sub: userId }, process.env.JWT_SECRET || "change__JOIN__me");
}
