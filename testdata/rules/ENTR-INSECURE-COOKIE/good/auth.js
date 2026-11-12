function login(req, res, token) {
  res.cookie("session", token, { httpOnly: true, secure: true });
}
