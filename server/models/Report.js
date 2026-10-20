import mongoose from "mongoose";

const { Schema } = mongoose;

const EventSchema = new Schema(
  {
    time: String,
    source: String,
    description: String,
    evidence: String,
  },
  { _id: false }
);

const ResultSchema = new Schema(
  {
    ip: String,
    status: String,
    risk_score: Number,
    attack_type: String,
    actions: [String],
    reason: String,
  },
  { _id: false }
);

const ReportSchema = new Schema({
  incidentId: { type: String, required: true, unique: true },
  incidentDate: String,
  incidentTime: String,
  analystName: String,
  systemAffected: String,
  severity: { type: String, required: true },

  attackerIp: { type: String, required: true },
  attackerUsername: String,
  targetedAccounts: String,
  firstSeen: String,
  lastSeen: String,
  observedEvents: Number,
  signalSummary: String,

  events: [EventSchema],

  summary: String,
  impact: String,
  recommendations: String,

  riskScore: Number,
  anomalyScore: Number,
  flags: [String],

  // Present only for live/dataset reports built from multiple results
  attackCounts: Schema.Types.Mixed,
  statusCounts: Schema.Types.Mixed,
  totalAttacks: Number,
  allResults: [ResultSchema],
  filename: String,

  source: { type: String, enum: ["live", "dataset", "simulation"], default: "live" },
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("Report", ReportSchema);
