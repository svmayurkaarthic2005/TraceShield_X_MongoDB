import mongoose from "mongoose";

export async function connectMongo(uri) {
  if (!uri) {
    console.warn("[mongo] MONGO_URI not set — reports API will return 503");
    return;
  }
  try {
    await mongoose.connect(uri);
    console.log("[mongo] connected");
  } catch (err) {
    console.warn("[mongo] connection failed, continuing without it:", err.message);
  }

  mongoose.connection.on("error", (err) => {
    console.warn("[mongo] connection error:", err.message);
  });
}

export function isMongoUp() {
  return mongoose.connection.readyState === 1;
}
