import { pool } from "@/lib/db";

export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
  return Response.json(rows);
}
