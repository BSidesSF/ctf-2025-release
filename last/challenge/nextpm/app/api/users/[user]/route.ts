import type {NextRequest} from "next/server";
import {NextResponse} from "next/server";
import {headers} from "next/headers";
import User from "@/models/user";
import AppConfig from "@/app/app.config";

function fail(error: string, status=403): NextResponse {
  return NextResponse.json({"error": error}, {status: status});
}

export async function GET(request: NextRequest, {params}: {params: Promise<{user: string}>}): Promise<NextResponse> {
  console.log("keybag request", request.url);
  const {user: username} = await params;
  if (username === undefined) {
    return fail("Bad Request", 400);
  }
  const rheaders = await headers();
  const authUser = rheaders.get(AppConfig.AUTH_MW_HEADER);
  if (authUser !== username && authUser != "admin") {
    return fail("Access denied", 403);
  }
  const user = User.getUser(username);
  if (!user) {
    return fail("Unknown user", 404);
  }
  return NextResponse.json(user);
}
