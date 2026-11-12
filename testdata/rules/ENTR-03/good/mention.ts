import { jwtVerify } from "jose";

// Do not use jwt.decode(token) here: it skips the signature check.
const NOTE = "jwt.decode(token) only reads the payload";

export async function claims(token: string, key: Uint8Array) {
  const { payload } = await jwtVerify(token, key, { algorithms: ["HS256"] });
  return { payload, note: NOTE };
}
