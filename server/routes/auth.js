import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const router = Router();

router.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required" });
  }

  const validUser = username === process.env.AUTH_USERNAME;
  const isPlainMatch = Boolean(process.env.AUTH_PASSWORD && password === process.env.AUTH_PASSWORD);
  const isHashMatch = Boolean(
    process.env.AUTH_PASSWORD_HASH && (await bcrypt.compare(password, process.env.AUTH_PASSWORD_HASH))
  );
  const validPass = validUser && (isPlainMatch || isHashMatch);
  if (!validUser || !validPass) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ sub: username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "12h",
  });
  res.json({ token });
});

export default router;
