import { pool } from "@/lib/db";

export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  // ruleid: NEXT-SQLI
  const { rows } = await pool.query(`SELECT * FROM users WHERE id = ${id}`);
  return Response.json(rows);
}
