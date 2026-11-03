import { Request, Response, NextFunction } from "express";
import { verifyToken, verifyClientToken, verifyRiderToken, extractTokenFromHeader } from "../utils/jwt.utils";
import { sendError, HTTP } from "../utils/response.utils";
import { JwtPayload, UserRole } from "../types/auth.types";
import User from "../models/user.model";

// Roles allowed into the staff console. "rider" exists on the User model but riders
// authenticate through their own collection and token (protectRider).
const STAFF_ROLES: UserRole[] = ["super_admin", "admin", "logistics_staff"];

export const protect = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader as string | undefined);

    if (!token) {
      sendError(
        res,
        "Access denied. No authentication token provided. Please log in to continue.",
        HTTP.UNAUTHORIZED, // 401
      );
      return;
    }
    const decodedPayload = verifyToken(token) as JwtPayload & { tokenType?: string };

    // Client and rider tokens are signed with the same secret, so reject them explicitly
    if (decodedPayload.tokenType) {
      sendError(res, "Invalid token type for this endpoint.", HTTP.UNAUTHORIZED);
      return;
    }

    // Re-check the account on every request so deactivation and role changes apply
    // immediately instead of when the token expires
    const user = await User.findById(decodedPayload.id).select("role isActive");
    if (!user || !user.isActive || !STAFF_ROLES.includes(user.role as UserRole)) {
      sendError(res, "Your account no longer has access. Please contact an administrator.", HTTP.UNAUTHORIZED);
      return;
    }

    req.user = { ...decodedPayload, role: user.role as UserRole };

    next();
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === "TokenExpiredError") {
        sendError(
          res,
          "Your session has expired. Please log in again to continue.",
          HTTP.UNAUTHORIZED,
        );
        return;
      }

      if (error.name === "JsonWebTokenError") {
        sendError(
          res,
          "Invalid authentication token. Please log in again to continue.",
          HTTP.UNAUTHORIZED,
        );
        return;
      }
    }

    sendError(
      res,
      "Authentication failed. Please log in again.",
      HTTP.UNAUTHORIZED,
    );
    return;
  }
};

export const protectClient = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader as string | undefined);

    if (!token) {
      sendError(res, "Access denied. No authentication token provided.", HTTP.UNAUTHORIZED);
      return;
    }

    const decoded = verifyClientToken(token);

    if (decoded.tokenType !== "client") {
      sendError(res, "Invalid token type for this endpoint.", HTTP.UNAUTHORIZED);
      return;
    }

    req.client = decoded;
    next();
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === "TokenExpiredError") {
        sendError(res, "Your session has expired. Please log in again.", HTTP.UNAUTHORIZED);
        return;
      }
      if (error.name === "JsonWebTokenError") {
        sendError(res, "Invalid authentication token.", HTTP.UNAUTHORIZED);
        return;
      }
    }
    sendError(res, "Authentication failed. Please log in again.", HTTP.UNAUTHORIZED);
  }
};

export const protectRider = (
  req: Request,
  res: Response,
  next: NextFunction,
): void => {
  try {
    const token = extractTokenFromHeader(req.headers.authorization as string | undefined);
    if (!token) {
      sendError(res, "Access denied. No authentication token provided.", HTTP.UNAUTHORIZED);
      return;
    }
    const decoded = verifyRiderToken(token);
    if (decoded.tokenType !== "rider") {
      sendError(res, "Invalid token type for this endpoint.", HTTP.UNAUTHORIZED);
      return;
    }
    req.rider = decoded;
    next();
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === "TokenExpiredError") {
        sendError(res, "Your session has expired. Please log in again.", HTTP.UNAUTHORIZED);
        return;
      }
      if (error.name === "JsonWebTokenError") {
        sendError(res, "Invalid authentication token.", HTTP.UNAUTHORIZED);
        return;
      }
    }
    sendError(res, "Authentication failed. Please log in again.", HTTP.UNAUTHORIZED);
  }
};

export const restrictTo = (...allowedRoles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      sendError(
        res,
        "Authentication required. Please log in.",
        HTTP.UNAUTHORIZED,
      );
      return;
    }

    const userRole = req.user.role;
    if (!allowedRoles.includes(userRole)) {
      sendError(
        res,
        `Access forbidden. This action requires the following role(s): ${allowedRoles.join(" or ")}. Your current role is: ${userRole}.`,
        HTTP.FORBIDDEN,
      );
      return;
    }

    next();
  };
};
