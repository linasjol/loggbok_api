import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import { promisify } from "util";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const scrypt = promisify(crypto.scrypt);

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

function stringArray(value) {
  if (!Array.isArray(value)) return [];

  return value
    .filter((item) => typeof item === "string")
    .map((item) => item.trim())
    .filter(Boolean);
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const key = await scrypt(password, salt, 64);

  return `scrypt:${salt}:${key.toString("hex")}`;
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    profile: user.profile
      ? {
          aircraftType: user.profile.aircraftType,
          categories: user.profile.categories,
          isSupervisor: user.profile.isSupervisor,
          supervisorCategories: user.profile.supervisorCategories,
          supervisorId: user.profile.supervisorId,
          updatedAt: user.profile.updatedAt
        }
      : null
  };
}

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

app.post("/api/auth/register", async (req, res) => {
  const {
    name,
    email,
    password,
    categories,
    aircraftType,
    isSupervisor,
    supervisorCategories,
    supervisorId
  } = req.body;

  const normalizedEmail = normalizeEmail(email);
  const trimmedName = typeof name === "string" ? name.trim() : "";

  if (!trimmedName || !normalizedEmail || typeof password !== "string") {
    return res.status(400).json({
      error: "name, email and password are required"
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error: "password must be at least 6 characters"
    });
  }

  try {
    const user = await prisma.user.create({
      data: {
        name: trimmedName,
        email: normalizedEmail,
        passwordHash: await hashPassword(password),
        profile: {
          create: {
            aircraftType:
              typeof aircraftType === "string" && aircraftType.trim()
                ? aircraftType.trim()
                : null,
            categories: stringArray(categories),
            isSupervisor: Boolean(isSupervisor),
            supervisorCategories: stringArray(supervisorCategories),
            supervisorId:
              typeof supervisorId === "string" && supervisorId.trim()
                ? supervisorId.trim()
                : null
          }
        }
      },
      include: {
        profile: true
      }
    });

    res.status(201).json({
      user: publicUser(user)
    });
  } catch (error) {
    if (error?.code === "P2002") {
      return res.status(409).json({
        error: "email is already registered"
      });
    }

    console.error("Register failed", error);
    res.status(500).json({
      error: "could not create user"
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
