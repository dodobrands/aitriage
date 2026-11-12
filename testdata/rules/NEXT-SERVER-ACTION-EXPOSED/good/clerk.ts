"use server";

import { currentUser } from "@clerk/nextjs/server";
import { db } from "@/lib/db";

export async function deletePost(id: string) {
  const user = await currentUser();
  if (!user) throw new Error("Unauthorized");
  await db.post.delete({ where: { id, authorId: user.id } });
}
