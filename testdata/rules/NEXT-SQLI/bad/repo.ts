import { prisma } from "@/lib/prisma";

export async function findByEmail(email: string) {
  // ruleid: NEXT-SQLI
  return prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`);
}
