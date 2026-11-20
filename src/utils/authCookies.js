import finalConfig from "../config/keys.js";

const base = { httpOnly: true, secure: finalConfig.env === "production", sameSite: "lax", path: "/" };

export const setAuthCookies = (res, { accessToken, refreshToken }) => {
  res.cookie("accessToken", accessToken, { ...base, maxAge: 15 * 60 * 1000 });
  res.cookie("refreshToken", refreshToken, { ...base, maxAge: 7 * 24 * 60 * 60 * 1000 });
};

export const clearAuthCookies = (res) => {
  res.clearCookie("accessToken", base);   // options must match the ones used to set them
  res.clearCookie("refreshToken", base);
};
