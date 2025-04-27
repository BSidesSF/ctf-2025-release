const AppConfig = {
  SECRET_KEY: process.env.SECRET_KEY || "meWantCookie!",
  AUTH_COOKIE_NAME: "nextpm",
  PUBLIC_ALLOWLIST: ["/", "/login"],
  AUTH_MW_HEADER: "X-Token-Username",
};

export default AppConfig;
