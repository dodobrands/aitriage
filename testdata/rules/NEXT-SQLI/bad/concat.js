import { db } from "@/lib/db";

export async function remove(id) {
  // ruleid: NEXT-SQLI
  return db.execute("DELETE FROM sessions WHERE user_id = " + id);
}
