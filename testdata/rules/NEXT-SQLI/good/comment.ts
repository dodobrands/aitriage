import { pool } from "@/lib/db";

// Never write pool.query(`SELECT * FROM users WHERE id = ${id}`); use parameters.
export async function byId(id: string) {
  return pool.query("SELECT * FROM users WHERE id = $1", [id]);
}
