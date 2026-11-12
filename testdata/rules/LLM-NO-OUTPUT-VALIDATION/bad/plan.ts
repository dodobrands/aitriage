export function readPlan(msg: Message) {
  // ruleid: LLM-NO-OUTPUT-VALIDATION
  const plan = JSON.parse(msg.content[0].text);
  return plan.steps;
}
