export default {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [{ key: "Content-Security-Policy", value: "default-src 'self'" }],
      },
    ];
  },
};
