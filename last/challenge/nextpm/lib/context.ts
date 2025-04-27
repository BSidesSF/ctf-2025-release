import { createContext } from "react";

export const UserContext = createContext({
  user: null,
  password: "",
  setUserPassword: () => {},
} as {
  user: string|null,
  password: string,
  setUserPassword: (username: string|null, password?: string) => void,
});
