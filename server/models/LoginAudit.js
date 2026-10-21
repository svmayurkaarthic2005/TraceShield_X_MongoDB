import mongoose from "mongoose";

const { Schema } = mongoose;

// One document per login attempt (success or failure) — the audit trail
// "production-level login" needs: who tried, from where, when, and whether
// it worked. Never stores the attempted password.
const LoginAuditSchema = new Schema({
  timestamp: { type: Date, default: Date.now },
  ip: String,
  userAgent: String,
  usernameAttempted: String,
  success: Boolean,
  reason: String, // e.g. "ok", "bad_credentials", "locked_out", "rate_limited"
});

export default mongoose.model("LoginAudit", LoginAuditSchema);
