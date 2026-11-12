/** @type {import('next').NextConfig} */
module.exports = {
  reactStrictMode: true,
  // ruleid: NEXT-CONFIG-ENV-SECRET
  env: {
    API_BASE_URL: process.env.API_BASE_URL,
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
  },
};
