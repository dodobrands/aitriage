export default {
  images: {
    // hostname: "**" would let anyone proxy images through this server.
    remotePatterns: [{ protocol: "https", hostname: "images.example.com", pathname: "/uploads/**" }],
  },
};
