const pg = require("pg");
const fs = require("fs");
module.exports = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true, ca: fs.readFileSync(process.env.PG_CA_PATH, "utf8") },
});
