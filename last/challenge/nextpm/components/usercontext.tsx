"use client";

import { useState } from "react";
import { UserContext } from "@/lib/context";

export default function UserContextComponent({children}: Readonly<{children: React.ReactNode}>) {
  const sessInfoKey = "nextpm";
  let currUser: string|null = null;
  let currPass = "";

  if ('sessionStorage' in globalThis) {
    const sessInfo = globalThis.sessionStorage.getItem(sessInfoKey);
    if (sessInfo) {
      console.log("Loading user session from sessionStorage");
      const si = JSON.parse(atob(sessInfo));
      currUser = si.user;
      currPass = si.password;
    }
  }

  const [info, setInfo] = useState({user: currUser, password: currPass} as {user: string|null, password: string});

  const setUserPass = (username: string|null, password?: string) => {
    const obj = {
      user: username,
      password: password || "",
    };
    const serObj = btoa(JSON.stringify(obj));
    window.sessionStorage.setItem(sessInfoKey, serObj);
    setInfo(obj);
  };

  return (
    <UserContext value={{user: info.user, password: info.password, setUserPassword: setUserPass}}>
      {children}
    </UserContext>
  );
}
