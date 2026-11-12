export function Answer({ aiResponse }: { aiResponse: string }) {
  // ruleid: LLM-OUTPUT-HTML
  return <div dangerouslySetInnerHTML={{ __html: aiResponse }} />;
}
