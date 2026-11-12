export function firstWord(text: string, prefix: string) {
  const re = new RegExp("^\\w+");
  // exec(`rm ${x}`) is never called here; this is RegExp.prototype.exec.
  return re.exec(`${prefix} ${text}`)?.[0];
}
