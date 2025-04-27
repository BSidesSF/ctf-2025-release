import * as fs from 'fs';

import User, { SetAllUsers } from '@/models/user';
import Keybag from '@/models/keybag';
import { KeySet } from '@/lib/keybagdata';

export async function setupUsers(): Promise<User[]> {
  const users: Promise<User[]> = new Promise((resolve) => {
      const newUsers = [
          {username: "admin", password: "othiu1Abiuc6uphahk1noW7kah3eimi", kbcb: emptyKeybag},
          {username: "bingo", password: "banditthedog", kbcb: flagKeybag},
          {username: "guest", password: "guest", disabled: false, kbcb: emptyKeybag},
      ];
      const uPromises: Promise<User>[] = [];
      newUsers.forEach((n) => {
        uPromises.push(new Promise((resolve) => {
          new User({...n, done: async (u: User) => {
            if (typeof n.kbcb === "function") {
              await n.kbcb(n);
            }
            resolve(u);
          }});
        }));
      });
      Promise.all(uPromises).then(resolve);
  });
  users.then((users) => {
    console.log("setup users", users.length);
    console.log(users);
    SetAllUsers(users);
  });
  return users;
}

async function emptyKeybag({username, password}: {username: string, password: string}) {
  const newkb = new Keybag({username: username});
  const ks = KeySet.fromJSON("[]");
  ks.setKey({
    site: "http://nextpm.localhost/",
    username: "guest",
    password: "guest",
  });
  await ks.updateKeybag(newkb, password);
  newkb.save();
}

async function flagKeybag({username, password}: {username: string, password: string}) {
  const newkb = new Keybag({username: username});
  const ks = KeySet.fromJSON("[]");
  ks.setKey({
    site: "http://nextpm.localhost/",
    username: "guest",
    password: "guest",
  });
  const flagVal = await getFlagValue();
  ks.setKey({
    site: "https://ctf.bsidessf.net/",
    username: "flag",
    password: flagVal,
  });
  await ks.updateKeybag(newkb, password);
  newkb.save();
}

async function getFlagValue(): Promise<string> {
  if ('CTF_FLAG' in process.env) {
    return process.env.CTF_FLAG || "";
  }
  if ('CTF_FLAG_FILE' in process.env) {
    return fs.readFileSync(process.env.CTF_FLAG_FILE || "", {
      encoding: "utf-8",
    });
  }
  console.log("no flag found");
  return "";
}
