import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

import { verifyRequestToken } from './lib/session';
import AppConfig from './app/app.config';

export async function middleware(request: NextRequest): Promise<NextResponse> {
  console.log('nextUrl', request.nextUrl.pathname);

  // check allowlist
  const is_public = AppConfig.PUBLIC_ALLOWLIST.find((item) => {
    if (item[item.length-1] == '*') {
      if (request.nextUrl.pathname.startsWith(item.substring(0, item.length-1))) {
        return true;
      }
    }
    return item == request.nextUrl.pathname;
  });

  if (is_public) {
    return NextResponse.next();
  }

  const token = await verifyRequestToken(request);
  if (token) {
    if (request.nextUrl.pathname == "/api/users" && token.username !== "admin") {
      return new NextResponse(null, {
        status: 403,
      });
    }
    console.log("token authenticated", token.username);
    const headers = new Headers(request.headers);
    headers.set(AppConfig.AUTH_MW_HEADER, token.username);
    return NextResponse.next({
      request: {
        headers: headers,
      }
    });
  }

  console.log("authn failed for path", request.nextUrl.pathname);
  return new NextResponse(null, {
    status: 403,
  });
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico, sitemap.xml, robots.txt (metadata files)
     */
    '/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt|images/|api/login).*)',
  ],
}
