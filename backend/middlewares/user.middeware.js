import jwt from "jsonwebtoken";
import { isBlacklisted } from "../services/tokenBlacklist.service.js";

export const authorisedUser = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "token not found" });
  }

  if (isBlacklisted(token)) {
    res.cookies("token", "");
    return res.json({ error: "Unauthorized user" }).status(401);
  }

  try {
    const decoded = jwt.verify(token, process.env.secret_key);
    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({ error: "Unauthorized" });
  }
};
