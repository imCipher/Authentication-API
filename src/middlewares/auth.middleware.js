import tokenUtils from "../utils/token.utils.js";
import ApiError from "../utils/ApiError.js";
import authService from "../modules/auth/auth.service.js";

export const protect = async (req, res, next) => {
  try {
    let token;
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    } else if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
      return next(
        ApiError.unauthorized(
          "You are not logged in! Please log in to get access."
        ),
      );
    }

    const decoded = await tokenUtils.verifyAccessToken(token);

    const currentUser = await authService.getUserById(
      decoded.sub,
      decoded.role,
    );

    if (!currentUser) {
      return next(
        ApiError.unauthorized(
          "The user belonging to this token no longer exists.",
        ),
      );
    }

    req.user = currentUser;
    next();
  } catch (error) {
    next(error);
  }
};
