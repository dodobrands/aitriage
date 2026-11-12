import { sql } from "@vercel/postgres";

export async function getUser(id: string) {
  const { rows } = await sql`SELECT * FROM users WHERE id = ${id}`;
  return rows[0];
}
