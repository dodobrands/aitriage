export async function run(db: Pool, generatedSql: string) {
  // ruleid: LLM-OUTPUT-SQL
  const rows = await db.query(generatedSql);
  return rows;
}
