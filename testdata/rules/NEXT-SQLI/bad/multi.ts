import { db } from "@/lib/db";

export async function search(term: string) {
  // ruleid: NEXT-SQLI
  return db.query(
    `SELECT id, title
       FROM posts
      WHERE title LIKE '%${term}%'`
  );
}
