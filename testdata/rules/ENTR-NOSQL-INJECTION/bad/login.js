async function login(req) {
  // ruleid: ENTR-NOSQL-INJECTION
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  return user;
}
