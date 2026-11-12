import { prisma } from "@/lib/prisma";

export async function getUser(email: string) {
  return prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`;
}
