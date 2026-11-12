import { z } from "zod";

const Plan = z.object({ steps: z.array(z.string()) });

export function readPlan(completion: Completion) {
  return Plan.parse(JSON.parse(completion.choices[0].message.content));
}
