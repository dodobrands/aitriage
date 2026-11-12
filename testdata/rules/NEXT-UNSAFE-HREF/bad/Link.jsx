export function Run({ code }) {
  // ruleid: NEXT-UNSAFE-HREF
  return <a href={`javascript:${code}`}>run</a>;
}
