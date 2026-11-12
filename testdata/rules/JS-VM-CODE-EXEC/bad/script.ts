import vm from "node:vm";

export function compile(source: string) {
  // ruleid: JS-VM-CODE-EXEC
  return new vm.Script(source);
}
