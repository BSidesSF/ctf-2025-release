import { hash, compare } from "bcrypt-ts";

export async function HashPassword(password: string): Promise<string> {
    try {
        return hash(password, 6);
    } catch(e) {
        console.log("error hashing password", e);
        throw e;
    }
}

export async function ValidatePassword(password: string, hash: string): Promise<boolean> {
    try {
        return compare(password, hash);
    } catch(e) {
        console.log("error validating password", e);
        return false;
    }
}