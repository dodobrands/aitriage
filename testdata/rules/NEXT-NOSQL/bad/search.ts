import { Post } from "@/models/post";

export async function POST(req: Request) {
  const body = await req.json();
  // ruleid: NEXT-NOSQL
  const posts = await Post.find(body);
  return Response.json(posts);
}
