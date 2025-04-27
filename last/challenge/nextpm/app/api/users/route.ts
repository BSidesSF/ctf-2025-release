import { NextResponse } from "next/server";
import { GetAllUsers } from "@/models/user";

type HandlerReturn = Promise<NextResponse>;

export async function GET(): HandlerReturn {
  return NextResponse.json(await GetAllUsers());
}

// Not implemented for registration
export async function POST(): HandlerReturn {
  return new NextResponse(null, {
    status: 400,
  });
}
