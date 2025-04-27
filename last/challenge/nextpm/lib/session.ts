import AppConfig from '../app/app.config';
import type { NextRequest } from 'next/server';

interface Token {
  readonly username: string;
}

const SEP = ".";

function getHMACKey(): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(AppConfig.SECRET_KEY);

  return crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function signString(str: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const key = await getHMACKey();
  const signature = await crypto.subtle.sign('HMAC', key, data);
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

export async function signToken(token: Token): Promise<string> {
  const data = btoa(JSON.stringify(token));
  const sig = await signString(data);
  return data + SEP + sig;
}

export async function verifyToken(token: string): Promise<Token|null> {
  const pieces = token.split(SEP);
  if (pieces.length != 2) {
    console.log("token has wrong number of pieces");
    return null;
  }
  const key = await getHMACKey();
  let sig;
  let databuf;
  let data;
  try {
    sig = Buffer.from(pieces[1], 'base64');
    data = atob(pieces[0]);
    databuf = Buffer.from(pieces[0]);
  } catch (e) {
    console.log('error decoding token pieces', e);
    return null;
  }
  const result = await crypto.subtle.verify('HMAC', key, sig, databuf);
  if (!result) {
    console.log('hmac signature verification failed');
    return null;
  }
  try {
    return JSON.parse(data) as Token;
  } catch (e) {
    console.log('error deserializing token', e);
    return null;
  }
}

export async function verifyRequestToken(request: NextRequest): Promise<Token|null> {
  const token = request.cookies.get(AppConfig.AUTH_COOKIE_NAME)?.value;
  if (typeof token !== "string" || token == "") {
    return null;
  }
  return verifyToken(token);
}
