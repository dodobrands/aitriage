import { redirect } from "next/navigation";

export default async function Page({ searchParams }: { searchParams: Promise<{ callbackUrl?: string }> }) {
  const sp = await searchParams;
  // ruleid: NEXT-OPEN-REDIRECT
  redirect(sp.callbackUrl ?? "/");
}
