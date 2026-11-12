import { execSync } from "child_process";

// ruleid: LLM-TOOL-SHELL-EXEC
server.tool("exec", { cmd: z.string() }, async ({ cmd }) => {
  const out = execSync(cmd).toString();
  return { content: [{ type: "text", text: out }] };
});
