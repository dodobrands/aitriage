import { createClient } from "@supabase/supabase-js";

export const adminClient = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  // ruleid: NEXT-PUBLIC-LEAK
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
);
