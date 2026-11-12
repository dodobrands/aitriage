import https from "https";
import axios from "axios";
import { readFileSync } from "fs";

// Do not set rejectUnauthorized: false; trust the internal CA instead.
export const api = axios.create({
  httpsAgent: new https.Agent({ ca: readFileSync("/etc/ssl/internal-ca.pem") }),
});
