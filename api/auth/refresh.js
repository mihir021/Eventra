import jwt from "jsonwebtoken";
import { getJwtSecret } from "./jwt-config.js";

const JWT_SECRET = getJwtSecret();
const ACCESS_TOKEN_EXPIRES_IN = "15m";

const corsHeaders = (req) => {
  const allowedOrigin = process.env.ALLOWED_ORIGIN || "*";
  const requestOrigin = req.headers?.origin;
  const isSpecificOrigin = allowedOrigin !== "*";
  
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    ...(isSpecificOrigin && { "Access-Control-Allow-Credentials": "true" }),
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
};

export default async function handler(req, res) {
  if (req.method === "OPTIONS") {
    return res.status(200).set(corsHeaders(req)).end();
  }

  if (req.method !== "POST") {
    return res.status(405).set(corsHeaders(req)).json({ error: "Method not allowed" });
  }

  try {
    let refreshToken = null;
    if (req.cookies && req.cookies.refresh_token) {
      refreshToken = req.cookies.refresh_token;
    } else if (req.headers.cookie) {
      const cookies = req.headers.cookie.split(";").map(c => c.trim());
      const rTokenCookie = cookies.find(c => c.startsWith("refresh_token="));
      if (rTokenCookie) {
        refreshToken = rTokenCookie.substring(14);
      }
    }

    if (!refreshToken) {
      return res.status(401).set(corsHeaders(req)).json({ error: "No refresh token provided" });
    }

    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    
    // Generate new access token
    const jwtPayload = {
      id: decoded.id,
      email: decoded.email,
      username: decoded.username,
      roles: decoded.roles,
      permissions: decoded.permissions,
    };

    const newAccessToken = jwt.sign(jwtPayload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });

    const isProd = process.env.NODE_ENV === "production";
    res.setHeader('Set-Cookie', `token=${newAccessToken}; HttpOnly; Path=/; Max-Age=900; SameSite=Strict${isProd ? '; Secure' : ''}`);

    return res.status(200).set(corsHeaders(req)).json({
      message: "Token refreshed successfully",
      token: newAccessToken,
    });
  } catch (error) {
    console.error("Refresh Error:", error);
    return res.status(401).set(corsHeaders(req)).json({ error: "Invalid or expired refresh token" });
  }
}
