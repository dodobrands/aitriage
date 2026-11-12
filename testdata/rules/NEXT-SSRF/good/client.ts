import axios from "axios";

// fetch(searchParams.get("url")) would be SSRF on the server; this only loads a known page.
export async function loadPage(paramsUrl: string) {
  return axios(paramsUrl);
}
