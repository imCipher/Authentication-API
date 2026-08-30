const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");
const { Strategy: GithubStrategy } = require("passport-github2");
const logger = require("../utils/logger");
const AuthService = require("../modules/auth/auth.service.js");
const finalConfig = require("./keys");

// Configure Google OAuth Strategy
if (finalConfig.googleOauth.clientId && finalConfig.googleOauth.clientSecret) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: finalConfig.googleOauth.clientId,
        clientSecret: finalConfig.googleOauth.clientSecret,
        callbackURL: finalConfig.googleOauth.callbackUrl,
        scope: ["profile", "email"],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          const email = profile.emails?.[0]?.value;
          const isEmailVerified = Boolean(
            profile.emails?.[0]?.verified || profile._json?.email_verified,
          );

          if (!email) {
            return done(
              new Error("No email associated with this Google account."),
              null,
            );
          }

          let user = await AuthService.oauthFindUser("GOOGLE", profile.id);
          if (!user) {
            const exixtingUser = await AuthService.oauthFindUserbyEmail(email);
            if (exixtingUser) {
              // Only link automatically if the email is verified by Google
              if (!isEmailVerified) {
                return done(new Error("Google email is not verified."), null);
              }
              user = await AuthService.oauthLinkAccount(
                exixtingUser.id,
                "GOOGLE",
                profile.id,
              );
            } else {
              user = await AuthService.oauthCreateUser("GOOGLE", profile);
            }
          }

          return done(null, user);
        } catch (err) {
          logger.error("Error in Google OAuth Strategy:", err);
          return done(err, false);
        }
      },
    ),
  );
}
