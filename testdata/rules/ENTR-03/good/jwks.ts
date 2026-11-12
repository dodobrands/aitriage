import jwt from "jsonwebtoken";
import { getSigningKey } from "./keys";

export async function verifyWithJwks(token: string) {
  const decoded = jwt.decode(token, { complete: true });
  const key = await getSigningKey(decoded?.header.kid);
  return jwt.verify(token, key, { algorithms: ["RS256"] });
}
