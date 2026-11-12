import path from "node:path";

export function download(req, res) {
  // ruleid: JS-PATH-TRAVERSAL
  res.sendFile(path.join(process.cwd(), "files", req.params.name));
}
