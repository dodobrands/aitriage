function login(req, res, token) {
  // ruleid: ENTR-INSECURE-COOKIE
  res.cookie("auth_token", token, {
    secure: true,
    sameSite: "lax",
  });
}
