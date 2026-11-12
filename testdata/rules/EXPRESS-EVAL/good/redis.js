// eval(code) is never used here; redis.eval runs a Lua script on the server.
async function incr(redis, key) {
  return redis.eval("return redis.call('INCR', KEYS[1])", 1, key);
}
async function title(page) {
  return page.$eval("h1", (el) => el.textContent);
}
const HELP = "do not call eval(input)";
module.exports = { incr, title, HELP };
