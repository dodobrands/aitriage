function safeUrl(raw: string): string {
  try {
    const u = new URL(raw);
    return ["http:", "https:", "mailto:"].includes(u.protocol) ? u.toString() : "#";
  } catch {
    return "#";
  }
}

export function Profile({ user }: { user: { website: string } }) {
  return <a href={safeUrl(user.website)}>Website</a>;
}
