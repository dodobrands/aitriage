// ruleid: NEXT-SERVER-ACTION-EXPOSED
"use server";

import { db } from "@/lib/db";

export async function deletePost(id: string) {
  await db.post.delete({ where: { id } });
}
