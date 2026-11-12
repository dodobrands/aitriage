// Rendering as children keeps React's escaping; no dangerouslySetInnerHTML needed.
export function Comment({ text }: { text: string }) {
  return <div className="comment" title="dangerouslySetInnerHTML is not used">{text}</div>;
}
