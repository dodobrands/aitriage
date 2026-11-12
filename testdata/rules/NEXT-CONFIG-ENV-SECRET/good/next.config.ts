import type { NextConfig } from "next";

const config: NextConfig = {
  env: {
    SITE_NAME: "Example",
    // STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY, (removed: read it in server code)
  },
};
export default config;
