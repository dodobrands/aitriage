"use client";

// Never read process.env.STRIPE_SECRET_KEY in this file; the server action does it.
export function Checkout({ action }: { action: () => Promise<void> }) {
  return <form action={action}><button>Pay</button></form>;
}
