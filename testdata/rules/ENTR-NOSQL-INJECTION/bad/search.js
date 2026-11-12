function byName(name) {
  // ruleid: ENTR-NOSQL-INJECTION
  return db.users.find({ $where: "this.name == '" + name + "'" });
}
