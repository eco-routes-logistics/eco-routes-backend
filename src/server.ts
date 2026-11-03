import express, { Application, RequestHandler } from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import mongoose from "mongoose";
import rateLimit from "express-rate-limit";

import { errorHandler } from "./middleware/errorHandler";
import apiRoutes from "./routes";

dotenv.config();

const connectDB = async (): Promise<void> => {
  const mongoUri = process.env.MONGODB_URI;

  if (!mongoUri) {
    console.error("Error: MONGODB_URI is not defined in environment variables");
    process.exit(1);
  }

  try {
    await mongoose.connect(mongoUri);
    console.log("✅ Connected to MongoDB");
  } catch (error) {
    console.error("❌ Failed to connect to MongoDB:", error);
    process.exit(1);
  }
};

const app: Application = express();
const PORT = process.env.PORT || 5000;

// ---------------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------------
app.use(helmet());
app.use(
  cors({
    origin: [
      "https://eccoroute.com",
      "https://www.eccoroute.com",
      "https://staging.eccoroute.com",
      "http://localhost:5173",
    ],
    credentials: true,
  }),
);

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

// General API rate limit — 100 req/min per IP (matches API_DOCUMENTATION.md spec)
app.set("trust proxy", 1);
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false,
  message: {
    status: "error",
    message: "Too many requests. Please wait a moment and try again.",
  },
});

// Stricter limit on auth endpoints to deter brute-force attacks
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: "error",
    message: "Too many authentication attempts. Please wait 15 minutes and try again.",
  },
});

app.use("/api/v1", apiLimiter as RequestHandler);
// Only the credential endpoints, for all three account types. Applying it to whole
// routers (e.g. /client-auth) also throttled normal page loads like /client-auth/me.
app.use(
  [
    "/api/v1/auth/login",
    "/api/v1/client-auth/login",
    "/api/v1/client-auth/register",
    "/api/v1/rider-auth/login",
    "/api/v1/rider-auth/register",
  ],
  authLimiter as RequestHandler,
);

app.use(morgan("dev"));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.status(200).json({
    status: "success",
    message: "EcoRoutes API is running",
    timestamp: new Date().toISOString(),
  });
});

app.use("/api/v1", apiRoutes);

app.use((req, res) => {
  res.status(404).json({
    status: "error",
    message: `Route ${req.originalUrl} not found`,
  });
});

app.use(errorHandler);

const shutdown = async (signal: string): Promise<void> => {
  console.log(`\n${signal} received — shutting down gracefully…`);
  await mongoose.disconnect();
  console.log("MongoDB disconnected");
  process.exit(0);
};

process.on("SIGTERM", () => { void shutdown("SIGTERM"); });
process.on("SIGINT", () => { void shutdown("SIGINT"); });

(async () => {
  await connectDB();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV || "development"} mode`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`API base:     http://localhost:${PORT}/api/v1`);
  });
})();

export default app;
