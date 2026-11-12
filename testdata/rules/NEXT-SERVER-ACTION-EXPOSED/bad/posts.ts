// Server actions for posts (no session check yet). ruleid: NEXT-SERVER-ACTION-EXPOSED
'use server'

import { db } from "@/lib/db";

// TODO: add session check, call auth() first
export async function deletePost(id: string) {
  await db.post.delete({ where: { id } });
}
