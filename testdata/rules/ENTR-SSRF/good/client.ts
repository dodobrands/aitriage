export async function load(queryUrl: string, requestUrlFromConfig: string) {
  await fetch(queryUrl);
  return fetch(requestUrlFromConfig);
}
