export function Legacy(props) {
  // ruleid: REACT-XSS
  return <section dangerouslySetInnerHTML={{ __html: props.body }} />;
}
