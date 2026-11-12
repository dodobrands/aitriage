// Shows connection details for the admin page.
"use client";

export function Status() {
  // ruleid: ENTR-09
  const url = process.env.DATABASE_URL;
  return <code>{url}</code>;
}
