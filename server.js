import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { promisify } from "util";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const scrypt = promisify(crypto.scrypt);

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

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

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function stringMap(value) {
  if (!isPlainObject(value)) return null;

  const result = {};
  for (const [key, mapValue] of Object.entries(value)) {
    const cleanKey = key.trim();
    if (!cleanKey || typeof mapValue !== "string" || !mapValue.trim()) {
      return null;
    }
    result[cleanKey] = mapValue.trim();
  }

  return result;
}

function dateStringMap(value) {
  const result = stringMap(value);
  if (result === null) return null;

  for (const date of Object.values(result)) {
    if (Number.isNaN(new Date(date).getTime())) return null;
  }

  return result;
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const key = await scrypt(password, salt, 64);

  return `scrypt:${salt}:${key.toString("hex")}`;
}

async function verifyPassword(password, passwordHash) {
  if (typeof password !== "string" || typeof passwordHash !== "string") {
    return false;
  }

  const [algorithm, salt, storedKey] = passwordHash.split(":");
  if (algorithm !== "scrypt" || !salt || !storedKey) return false;

  const key = await scrypt(password, salt, 64);
  const storedBuffer = Buffer.from(storedKey, "hex");

  if (storedBuffer.length !== key.length) return false;

  return crypto.timingSafeEqual(storedBuffer, key);
}

function createToken(user) {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is not configured");
  }

  return jwt.sign(
    {
      sub: user.id,
      email: user.email
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function authenticate(req, res, next) {
  const authHeader = req.get("authorization") ?? "";
  const [scheme, token] = authHeader.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      error: "missing bearer token"
    });
  }

  if (!JWT_SECRET) {
    return res.status(500).json({
      error: "JWT_SECRET is not configured"
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload?.sub) {
      return res.status(401).json({
        error: "invalid token"
      });
    }

    const user = await prisma.user.findUnique({
      where: {
        id: payload.sub
      },
      include: {
        profile: true
      }
    });

    if (!user) {
      return res.status(401).json({
        error: "invalid token"
      });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      error: "invalid token"
    });
  }
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

function publicSignature(signature) {
  return {
    id: signature.id,
    activityId: signature.activityId,
    signedByUserId: signature.signedByUserId,
    supervisorName: signature.supervisorName,
    supervisorId: signature.supervisorId,
    signedAt: signature.signedAt,
    createdAt: signature.createdAt
  };
}

function publicActivity(activity) {
  return {
    id: activity.id,
    date: activity.date,
    aircraftType: activity.aircraftType,
    categories: activity.categories,
    activity: activity.activity,
    taskTypes: activity.taskTypes,
    materialGroups: activity.materialGroups,
    timeSpentMinutes: activity.timeSpentMinutes,
    workOrder: activity.workOrder,
    notes: activity.notes,
    isHangarDuty: activity.isHangarDuty,
    certIds: activity.certIds,
    signatures: Array.isArray(activity.signatures)
      ? activity.signatures.map(publicSignature)
      : [],
    isSigned: Array.isArray(activity.signatures) && activity.signatures.length > 0,
    createdAt: activity.createdAt,
    updatedAt: activity.updatedAt,
    deletedAt: activity.deletedAt
  };
}

function parseActivityDate(value) {
  if (typeof value !== "string") return null;

  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function parseTimeSpentMinutes(value) {
  if (!Number.isInteger(value) || value < 0) return null;
  return value;
}

function activityUpdateData(body) {
  const data = {};

  if (Object.hasOwn(body, "date")) {
    const date = parseActivityDate(body.date);
    if (!date) return { error: "date must be a valid ISO date string" };
    data.date = date;
  }

  if (Object.hasOwn(body, "aircraftType")) {
    if (typeof body.aircraftType !== "string" || !body.aircraftType.trim()) {
      return { error: "aircraftType must not be empty" };
    }
    data.aircraftType = body.aircraftType.trim();
  }

  if (Object.hasOwn(body, "activity")) {
    if (typeof body.activity !== "string" || !body.activity.trim()) {
      return { error: "activity must not be empty" };
    }
    data.activity = body.activity.trim();
  }

  if (Object.hasOwn(body, "timeSpentMinutes")) {
    const minutes = parseTimeSpentMinutes(body.timeSpentMinutes);
    if (minutes === null) {
      return { error: "timeSpentMinutes must be a non-negative integer" };
    }
    data.timeSpentMinutes = minutes;
  }

  if (Object.hasOwn(body, "categories")) {
    data.categories = stringArray(body.categories);
  }

  if (Object.hasOwn(body, "taskTypes")) {
    data.taskTypes = stringArray(body.taskTypes);
  }

  if (Object.hasOwn(body, "materialGroups")) {
    data.materialGroups = stringArray(body.materialGroups);
  }

  if (Object.hasOwn(body, "workOrder")) {
    data.workOrder =
      typeof body.workOrder === "string" && body.workOrder.trim()
        ? body.workOrder.trim()
        : null;
  }

  if (Object.hasOwn(body, "notes")) {
    data.notes = stringArray(body.notes);
  }

  if (Object.hasOwn(body, "isHangarDuty")) {
    data.isHangarDuty = Boolean(body.isHangarDuty);
  }

  if (Object.hasOwn(body, "certIds")) {
    data.certIds = stringArray(body.certIds);
  }

  return { data };
}

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

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail || typeof password !== "string") {
    return res.status(400).json({
      error: "email and password are required"
    });
  }

  try {
    const user = await prisma.user.findUnique({
      where: {
        email: normalizedEmail
      },
      include: {
        profile: true
      }
    });

    if (!user || !(await verifyPassword(password, user.passwordHash))) {
      return res.status(401).json({
        error: "invalid email or password"
      });
    }

    res.json({
      token: createToken(user),
      user: publicUser(user)
    });
  } catch (error) {
    console.error("Login failed", error);
    res.status(500).json({
      error: "could not log in"
    });
  }
});

app.get("/api/me", authenticate, (req, res) => {
  res.json({
    user: publicUser(req.user)
  });
});

app.get("/api/progress-preferences", authenticate, async (req, res) => {
  try {
    const preferences = await prisma.progressPreference.findUnique({
      where: {
        userId: req.user.id
      }
    });

    res.json({
      progressPreferences: {
        pathSelections: preferences?.pathSelections ?? {},
        startDates: preferences?.startDates ?? {},
        updatedAt: preferences?.updatedAt ?? null
      }
    });
  } catch (error) {
    console.error("Get progress preferences failed", error);
    res.status(500).json({
      error: "could not load progress preferences"
    });
  }
});

app.put("/api/progress-preferences", authenticate, async (req, res) => {
  const pathSelections = stringMap(req.body.pathSelections ?? {});
  const startDates = dateStringMap(req.body.startDates ?? {});

  if (pathSelections === null) {
    return res.status(400).json({
      error: "pathSelections must be an object of string values"
    });
  }

  if (startDates === null) {
    return res.status(400).json({
      error: "startDates must be an object of ISO date string values"
    });
  }

  try {
    const preferences = await prisma.progressPreference.upsert({
      where: {
        userId: req.user.id
      },
      create: {
        userId: req.user.id,
        pathSelections,
        startDates
      },
      update: {
        pathSelections,
        startDates
      }
    });

    res.json({
      progressPreferences: {
        pathSelections: preferences.pathSelections,
        startDates: preferences.startDates,
        updatedAt: preferences.updatedAt
      }
    });
  } catch (error) {
    console.error("Save progress preferences failed", error);
    res.status(500).json({
      error: "could not save progress preferences"
    });
  }
});

app.get("/api/activities", authenticate, async (req, res) => {
  try {
    const activities = await prisma.activity.findMany({
      where: {
        userId: req.user.id,
        deletedAt: null
      },
      include: {
        signatures: {
          orderBy: {
            signedAt: "desc"
          }
        }
      },
      orderBy: [
        {
          date: "desc"
        },
        {
          createdAt: "desc"
        }
      ]
    });

    res.json({
      activities: activities.map(publicActivity)
    });
  } catch (error) {
    console.error("Get activities failed", error);
    res.status(500).json({
      error: "could not load activities"
    });
  }
});

app.post("/api/activities", authenticate, async (req, res) => {
  const {
    date,
    aircraftType,
    categories,
    activity,
    taskTypes,
    materialGroups,
    timeSpentMinutes,
    workOrder,
    notes,
    isHangarDuty,
    certIds
  } = req.body;

  const parsedDate = parseActivityDate(date);
  const parsedMinutes = parseTimeSpentMinutes(timeSpentMinutes);
  const trimmedAircraftType =
    typeof aircraftType === "string" ? aircraftType.trim() : "";
  const trimmedActivity = typeof activity === "string" ? activity.trim() : "";

  if (!parsedDate || !trimmedAircraftType || !trimmedActivity) {
    return res.status(400).json({
      error: "date, aircraftType and activity are required"
    });
  }

  if (parsedMinutes === null) {
    return res.status(400).json({
      error: "timeSpentMinutes must be a non-negative integer"
    });
  }

  try {
    const created = await prisma.activity.create({
      data: {
        userId: req.user.id,
        date: parsedDate,
        aircraftType: trimmedAircraftType,
        categories: stringArray(categories),
        activity: trimmedActivity,
        taskTypes: stringArray(taskTypes),
        materialGroups: stringArray(materialGroups),
        timeSpentMinutes: parsedMinutes,
        workOrder:
          typeof workOrder === "string" && workOrder.trim()
            ? workOrder.trim()
            : null,
        notes: stringArray(notes),
        isHangarDuty: Boolean(isHangarDuty),
        certIds: stringArray(certIds)
      },
      include: {
        signatures: true
      }
    });

    res.status(201).json({
      activity: publicActivity(created)
    });
  } catch (error) {
    console.error("Create activity failed", error);
    res.status(500).json({
      error: "could not create activity"
    });
  }
});

app.get("/api/activities/:id", authenticate, async (req, res) => {
  try {
    const activity = await prisma.activity.findFirst({
      where: {
        id: req.params.id,
        userId: req.user.id,
        deletedAt: null
      },
      include: {
        signatures: {
          orderBy: {
            signedAt: "desc"
          }
        }
      }
    });

    if (!activity) {
      return res.status(404).json({
        error: "activity not found"
      });
    }

    res.json({
      activity: publicActivity(activity)
    });
  } catch (error) {
    console.error("Get activity failed", error);
    res.status(500).json({
      error: "could not load activity"
    });
  }
});

app.put("/api/activities/:id", authenticate, async (req, res) => {
  const { data, error } = activityUpdateData(req.body);

  if (error) {
    return res.status(400).json({ error });
  }

  try {
    const existing = await prisma.activity.findFirst({
      where: {
        id: req.params.id,
        userId: req.user.id,
        deletedAt: null
      }
    });

    if (!existing) {
      return res.status(404).json({
        error: "activity not found"
      });
    }

    const updated = await prisma.activity.update({
      where: {
        id: existing.id
      },
      data,
      include: {
        signatures: {
          orderBy: {
            signedAt: "desc"
          }
        }
      }
    });

    res.json({
      activity: publicActivity(updated)
    });
  } catch (error) {
    console.error("Update activity failed", error);
    res.status(500).json({
      error: "could not update activity"
    });
  }
});

app.delete("/api/activities/:id", authenticate, async (req, res) => {
  try {
    const existing = await prisma.activity.findFirst({
      where: {
        id: req.params.id,
        userId: req.user.id,
        deletedAt: null
      }
    });

    if (!existing) {
      return res.status(404).json({
        error: "activity not found"
      });
    }

    const deleted = await prisma.activity.update({
      where: {
        id: existing.id
      },
      data: {
        deletedAt: new Date()
      },
      include: {
        signatures: {
          orderBy: {
            signedAt: "desc"
          }
        }
      }
    });

    res.json({
      activity: publicActivity(deleted)
    });
  } catch (error) {
    console.error("Delete activity failed", error);
    res.status(500).json({
      error: "could not delete activity"
    });
  }
});

app.post("/api/activities/:id/signature", authenticate, async (req, res) => {
  const profile = req.user.profile;

  if (!profile?.isSupervisor) {
    return res.status(403).json({
      error: "only supervisors can sign activities"
    });
  }

  try {
    const activity = await prisma.activity.findFirst({
      where: {
        id: req.params.id,
        deletedAt: null
      }
    });

    if (!activity) {
      return res.status(404).json({
        error: "activity not found"
      });
    }

    if (activity.userId === req.user.id) {
      return res.status(400).json({
        error: "supervisors cannot sign their own activities"
      });
    }

    const signature = await prisma.activitySignature.create({
      data: {
        activityId: activity.id,
        signedByUserId: req.user.id,
        supervisorName: req.user.name,
        supervisorId: profile.supervisorId,
        signedAt: new Date()
      }
    });

    res.status(201).json({
      signature: publicSignature(signature)
    });
  } catch (error) {
    console.error("Sign activity failed", error);
    res.status(500).json({
      error: "could not sign activity"
    });
  }
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
