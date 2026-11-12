"use client";

export default function Billing() {
  // ruleid: ENTR-09
  const key = process.env.STRIPE_SECRET_KEY;
  return <pre>{key}</pre>;
}
