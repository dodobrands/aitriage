import { redirect } from "next/navigation";

// Do not call redirect(searchParams.get("next")) without checking the path.
export default async function Login() {
  redirect("/dashboard");
}
