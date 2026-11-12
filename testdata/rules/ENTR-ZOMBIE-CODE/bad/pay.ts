export function pay(amount: number) {
  // ruleid: ENTR-ZOMBIE-CODE
  /* OLD CODE
  return legacyPay(amount);
  */
  return gateway.pay(amount);
}
