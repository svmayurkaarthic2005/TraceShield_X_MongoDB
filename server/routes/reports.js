import { Router } from "express";
import Report from "../models/Report.js";
import { isMongoUp } from "../config/db.js";

const router = Router();

router.use((req, res, next) => {
  if (!isMongoUp()) return res.status(503).json({ error: "MongoDB unavailable" });
  next();
});

router.post("/", async (req, res) => {
  const { incidentId, severity, attackerIp } = req.body || {};
  if (!incidentId || !severity || !attackerIp) {
    return res.status(400).json({
      error: "incidentId, severity, and attackerIp are required",
    });
  }

  const report = await Report.findOneAndUpdate(
    { incidentId },
    { $set: req.body },
    { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true }
  );
  res.json(report);
});

router.get("/", async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 200);
  const skip = parseInt(req.query.skip, 10) || 0;

  const reports = await Report.find()
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .select("incidentId incidentDate incidentTime severity attackerIp systemAffected riskScore source createdAt");

  res.json(reports);
});

router.get("/:id", async (req, res) => {
  const report = await Report.findOne({ incidentId: req.params.id });
  if (!report) return res.status(404).json({ error: "Report not found" });
  res.json(report);
});

router.delete("/:id", async (req, res) => {
  const result = await Report.deleteOne({ incidentId: req.params.id });
  if (result.deletedCount === 0) return res.status(404).json({ error: "Report not found" });
  res.status(204).end();
});

export default router;
