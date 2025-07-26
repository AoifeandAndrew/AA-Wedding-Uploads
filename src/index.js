export default {
  async fetch() {
    return new Response("Hello, world! Your Worker lives 🎉", {
      headers: { "content-type": "text/plain" },
    });
  },
};
