const HINT = 'Links like href="javascript:void(0)" are blocked by React 19';

export function Menu({ onOpen }: { onOpen: () => void }) {
  {/* Use a button instead of href="javascript:..." */}
  return <button type="button" title={HINT} onClick={onOpen}>Open</button>;
}
