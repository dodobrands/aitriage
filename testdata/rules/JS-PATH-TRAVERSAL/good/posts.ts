import fs from "fs";
import path from "path";

const postsDirectory = path.join(`${process.cwd()}/content/posts`);

export function getPost(slug: string) {
  return fs.readFileSync(path.join(postsDirectory, `${slug}.md`), "utf8");
}
