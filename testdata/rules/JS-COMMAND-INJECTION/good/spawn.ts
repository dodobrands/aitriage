import { spawn } from "child_process";

export function build(bin: string, args: string[]) {
  return spawn(`${bin}`, args, { stdio: "inherit" });
}
