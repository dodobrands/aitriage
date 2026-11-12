function parse(color, pattern, response) {
  const result = /#([0-9a-f]{6})/i.exec(color);
  const match = pattern.exec(response.text);
  return [result, match];
}
