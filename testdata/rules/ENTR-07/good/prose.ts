// Note: any caller may pass a partial object, such as any other config.
export const HELP = "field type: any value is accepted";

export function withDefaults(input: Partial<{ debug: boolean }>): { debug: boolean } {
  return { debug: input.debug ?? false };
}
