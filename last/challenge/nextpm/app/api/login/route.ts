import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import User from '@/models/user';
import { signToken } from '@/lib/session';
import AppConfig from '@/app/app.config';

export async function POST(request: NextRequest): Promise<NextResponse> {
  const fail = function(e: string): NextResponse {
    return NextResponse.json({'error': e}, {'status': 403});
  };
  let username: string | undefined;
  let password: string | undefined;
  try {
    ({username, password} = await request.json());
  } catch(e) {
    console.log('bad json in request', e);
    return fail('Bad JSON');
  }
  if (username == undefined || password == undefined) {
    return fail('Missing required field');
  }
  const user = await User.loginUser(username, password);
  if (!user) {
    return fail('Invalid username/password');
  }
  const token = {'username': user.username};
  const signed = await signToken(token);
  const respBody = {
    'user': user,
    'token': signed,
  };
  const resp = NextResponse.json(respBody);
  resp.cookies.set(AppConfig.AUTH_COOKIE_NAME, signed);
  return resp;
}
