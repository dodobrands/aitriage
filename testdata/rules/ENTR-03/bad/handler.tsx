import jwt from "jsonwebtoken";

export default async function Page({ token }: { token: string }) {
  // ruleid: ENTR-03
  const claims = jwt.decode(token) as { role: string } | null;
  return claims?.role === "admin" ? <section>admin</section> : null;
}
