"use server";

export async function importFeed(formData: FormData) {
  // ruleid: NEXT-SSRF
  const res = await fetch(formData.get("feedUrl") as string);
  return res.text();
}
