export const comments = pgTable("comments", { search: sql`to_tsvector(body)`, response: text("response") });
