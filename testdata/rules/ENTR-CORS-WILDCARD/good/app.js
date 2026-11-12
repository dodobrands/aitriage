app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
window.parent.postMessage(payload, targetOrigin);
