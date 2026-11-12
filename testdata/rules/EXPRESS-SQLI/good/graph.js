async function run(client, fields) {
  return client.query(`{ viewer { ${fields} } }`);
}
module.exports = { run };
