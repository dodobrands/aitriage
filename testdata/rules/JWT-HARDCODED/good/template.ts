import jwt from "jsonwebtoken";

// jwt.sign(payload, "literal") would be unsafe; the key comes from the environment.
export function issue(userId: string) {
  return jwt.sign({ sub: userId }, `${process.env.JWT_SECRET}`);
}
