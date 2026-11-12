import DOMPurify from "isomorphic-dompurify";

export function Comment({ html }: { html: string }) {
  return <div className="comment" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
