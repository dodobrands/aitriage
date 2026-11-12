export function Menu() {
  // ruleid: NEXT-UNSAFE-HREF
  return <a href="javascript:void(0)" onClick={() => alert("hi")}>Open</a>;
}
