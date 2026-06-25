import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Temporary in-memory "database".
// It disappears when the server restarts.
// Later, we will replace this with a real database.
let entries = [];

// Test endpoint
app.get("/api/health", async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;

    res.json({
      status: "ok",
      database: "ok",
      message: "Logbook API is working"
    });
  } catch (error) {
    console.error("Health check failed", error);
    res.status(503).json({
      status: "error",
      database: "unavailable",
      message: "Logbook API cannot reach the database"
    });
  }
});

// Get all logbook entries
app.get("/api/entries", (req, res) => {
  res.json(entries);
});

// Create a new logbook entry
app.post("/api/entries", (req, res) => {
  const { title, body } = req.body;

  if (!title || !body) {
    return res.status(400).json({
      error: "title and body are required"
    });
  }

  const entry = {
    id: crypto.randomUUID(),
    title,
    body,
    createdAt: new Date().toISOString()
  };

  entries.push(entry);

  res.status(201).json(entry);
});

// Get a specific entry
app.get("/api/entries/:id", (req, res) => {
  const entry = entries.find((item) => item.id === req.params.id);

  if (!entry) {
    return res.status(404).json({
      error: "Entry not found"
    });
  }

  res.json(entry);
});

// Start the server
app.listen(PORT, () => {
  console.log(`Logbook API is running on http://localhost:${PORT}`);
});

process.on("SIGINT", async () => {
  await prisma.$disconnect();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  await prisma.$disconnect();
  process.exit(0);
});
