export async function viewer(client: { query: (q: string) => Promise<unknown> }, fields: string) {
  return client.query(`{ viewer { ${fields} } }`);
}
