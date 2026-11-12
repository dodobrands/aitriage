export function Comment({ html }: { html: string }) {
  // ruleid: REACT-XSS
  return <div className="comment" dangerouslySetInnerHTML={{ __html: html }} />;
}
