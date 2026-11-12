import https from "https";
import axios from "axios";

export const api = axios.create({
  // ruleid: JS-TLS-VERIFY-OFF
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
});
