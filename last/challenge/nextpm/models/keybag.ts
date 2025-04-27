import { randomBytes } from "crypto";

interface keybagConstructorArgs {
  username: string;
  version?: number;
  salt?: string;
  keybag?: string;
}

export default class Keybag {
  username: string;
  version = 1;
  salt: string;
  keybag: string;

  constructor(args: keybagConstructorArgs) {
    const {
      username,
      version,
      salt,
      keybag,
    } = args;
    this.username = username;
    if (version !== undefined) {
      this.version = version;
    }
    if (typeof salt == "string" && salt.length > 0) {
      this.salt = salt;
    } else {
      this.salt = genSalt();
    }
    this.keybag = keybag || "";
  }

  static Get(username: string): Keybag|null {
    const found = globalThis.keyring.find((kb) => {
      console.log("get keybag", kb.username, username);
      return kb.username === username;
    });
    return found || null;
  }

  save() {
    const ring = globalThis.keyring.filter((kb) => {
      return kb.username !== this.username;
    });
    ring.push(this);
    globalThis.keyring = ring;
    console.log('Saved keybag for ', this.username);
  }
};

function genSalt(): string {
  const salt_len = 12;
  const rngbytes = randomBytes(salt_len);
  return rngbytes.toString('base64');
}

declare global {
  var keyring: Keybag[];
}

if (!('keyring' in globalThis)) {
  globalThis.keyring = Array();
}
