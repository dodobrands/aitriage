"use server";

import { auth } from "@/auth";
import { db } from "@/lib/db";

export async function deletePost(id: string) {
  const session = await auth();
  if (!session?.user) throw new Error("Unauthorized");
  await db.post.delete({ where: { id, authorId: session.user.id } });
}
