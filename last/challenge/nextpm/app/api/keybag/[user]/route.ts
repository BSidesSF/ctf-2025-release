import type {NextRequest} from "next/server";
import {NextResponse} from "next/server";
import User from "@/models/user";
import Keybag from "@/models/keybag";

function fail(error: string, status=403): NextResponse {
  return NextResponse.json({"error": error}, {status: status});
}

async function getKeybagUser(username: string): Promise<User|null> {
  if (typeof username !== "string")
    return null;
  return User.getUser(username);
}

export async function GET(request: NextRequest, {params}: {params: Promise<{user: string}>}): Promise<NextResponse> {
  console.log("keybag request", request.url);
  const {user: username} = await params;
  const user = await getKeybagUser(username);
  if (!user) {
    return fail("no user found", 404);
  }
  const keybag = Keybag.Get(user.username);
  if (!keybag) {
    return fail("no keybag found", 404);
  }
  return NextResponse.json(keybag);
}

export async function POST(): Promise<NextResponse> {
  return fail("not authorized", 403);
}
