function compile(userTemplate) {
  // ruleid: ENTR-EVAL-FUNC
  return new Function("data", userTemplate);
}
