// ruleid: ENTR-INSECURE-RANDOM
function generateToken() {
  return Math.random().toString(36).substring(2);
}
