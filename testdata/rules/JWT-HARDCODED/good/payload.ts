import jwt from "jsonwebtoken";

export function issue(key: string) {
  return jwt.sign("static-subject", key);
}
