import mongoose from "mongoose";

const { Schema } = mongoose;

// Singleton document (there is exactly one operator account) holding the
// MUTABLE parts of login state: the current password hash and lockout
// counters. AUTH_USERNAME/AUTH_PASSWORD_HASH in .env remain the bootstrap
// values used to seed this document on first run (and the fallback used
// when MongoDB is unreachable) — but once seeded, a password change updates
// this document, not the environment, since a running process can't durably
// rewrite its own .env (and on Render, env vars are managed outside the app
// entirely).
const AuthStateSchema = new Schema({
  _id: { type: String, default: "singleton" },
  passwordHash: { type: String, required: true },
  failedAttempts: { type: Number, default: 0 },
  lockedUntil: { type: Date, default: null },
  updatedAt: { type: Date, default: Date.now },
});

export default mongoose.model("AuthState", AuthStateSchema);
