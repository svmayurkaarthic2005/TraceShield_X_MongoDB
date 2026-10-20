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
  const validPass = validUser && (await bcrypt.compare(password, process.env.AUTH_PASSWORD_HASH || ""));
  if (!validUser || !validPass) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ sub: username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "12h",
  });
  res.json({ token });
});

export default router;
