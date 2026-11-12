server.tool("match", { text: z.string() }, async ({ text }) => {
  const m = /order-(\d+)/.exec(text);
  return { content: [{ type: "text", text: m ? m[1] : "" }] };
});
