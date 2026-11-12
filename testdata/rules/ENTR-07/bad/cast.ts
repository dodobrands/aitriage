export function readFoo(z: unknown) {
  // ruleid: ENTR-07
  return (z as any).foo;
}
