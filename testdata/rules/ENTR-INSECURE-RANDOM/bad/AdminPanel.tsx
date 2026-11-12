export function createAccount(email: string) {
  // ruleid: ENTR-INSECURE-RANDOM
  const tempPassword = Math.random().toString(36).slice(-8);
  return api.invite(email, tempPassword);
}
