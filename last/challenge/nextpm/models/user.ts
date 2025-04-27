import { HashPassword, ValidatePassword } from "@/lib/password";

export default class User {
    username: string;
    passwordHash: string;
    disabled = true;

    constructor({username, password, passwordHash, disabled, done}: {username: string, password?: string|null|undefined, passwordHash?: string|null|undefined, disabled?: boolean, done?:((arg0: User)=>void)}) {
        this.username = username;
        if (disabled !== undefined) {
          this.disabled = disabled;
        }
        if (typeof passwordHash == "string") {
            this.passwordHash = passwordHash;
            if (done) done(this);
        } else if (typeof password == "string") {
            this.passwordHash = "";
            const item = this;
            HashPassword(password).then((res) => {
                item.passwordHash = res;
                if (done) done(this);
            });
        } else {
            throw "Need password or passwordHash!";
        }
    }

    static async getUser(username: string): Promise<User|null> {
        return (await GetAllUsers()).find((u) => {return u.username === username}) || null;
    }

    static async loginUser(username: string, password: string): Promise<User|null> {
        const user = await User.getUser(username);
        if (!user) {
            console.log('could not find user', username);
            return null;
        }
        if (user.disabled) {
            console.log('user is disabled', username);
            return null;
        }
        const ok = await ValidatePassword(password, user.passwordHash);
        if (ok) {
            return user;
        }
        console.log('invalid password for user', username);
        return null;
    }
};

if (!('userdb' in globalThis)) {
  globalThis.userdb = [];
  console.log('reset _users');
}

export async function GetAllUsers(): Promise<User[]> {
  console.log("gau", globalThis.userdb);
  return globalThis.userdb;
}

export function SetAllUsers(users: User[]) {
  globalThis.userdb = users;
  console.log("sau", globalThis.userdb);
}

declare global {
    var userdb: User[];
}