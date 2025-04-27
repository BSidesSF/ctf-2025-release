import type Keybag from '@/models/keybag';
import sodium from 'libsodium-wrappers-sumo';

export interface KeybagEntry {
  site: string;
  username: string;
  password: string;
}

function isKeybagEntry(obj: unknown): obj is KeybagEntry {
  if (obj === null || obj === undefined)
    return false;
  const o = obj as KeybagEntry;
  return (typeof o.site === "string" &&
          typeof o.username === "string" &&
          typeof o.password === "string");
}

function toKeybagEntry(obj: unknown): KeybagEntry {
  if (isKeybagEntry(obj)) {
    return obj as KeybagEntry;
  }
  throw new Error("object is not a valid keybag entry!");
}

export class KeySet {
  private keys: Record<string, KeybagEntry>;

  constructor() {
    this.keys = {};
  }

  static fromJSON(data: string): KeySet {
    const keys: Record<string, KeybagEntry> = {};
    const parsed = JSON.parse(data);
    for (let i=0; i<parsed.length; i++) {
      const e = toKeybagEntry(parsed[i]);
      keys[e.site] = e;
    }
    const ks = new KeySet();
    ks.keys = keys;
    return ks;
  }

  toJSON(): string {
    return JSON.stringify(Object.values(this.keys));
  }

  getKeys(): KeybagEntry[] {
    return Object.values(this.keys);
  }

  getKey(site: string): (KeybagEntry | null) {
    return this.keys[site] || null;
  }

  setKey(e: KeybagEntry) {
    this.keys[e.site] = e;
  }

  static async fromKeybag(kb: Keybag, password: string): Promise<KeySet> {
    await sodium.ready;
    const key = KeySet.deriveKey(kb, password);
    const salt = sodium.from_base64(kb.salt);
    const ciphertext = sodium.from_base64(kb.keybag);
    const plaintext = sodium.crypto_secretbox_open_easy(ciphertext, salt, key);
    return KeySet.fromJSON(sodium.to_string(plaintext));
  }

  // stores into the keybag, but doesn't save
  async updateKeybag(kb: Keybag, password: string) {
    await sodium.ready;
    console.log(Object.keys(sodium));
    const newSalt = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const plaintext = sodium.from_string(this.toJSON());
    const key = KeySet.deriveKey(kb, password);
    const ciphertext = sodium.crypto_secretbox_easy(plaintext, newSalt, key);
    kb.version += 1;
    kb.salt = sodium.to_base64(newSalt);
    kb.keybag = sodium.to_base64(ciphertext);
  }

  private static deriveKey(kb: Keybag, password: string): Uint8Array {
    const pwsalt = sodium.crypto_generichash(sodium.crypto_pwhash_SALTBYTES, kb.username);
    return sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      password,
      pwsalt,
      sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      sodium.crypto_pwhash_MEMLIMIT_MIN*4,
      sodium.crypto_pwhash_ALG_ARGON2ID13);
  }
}
