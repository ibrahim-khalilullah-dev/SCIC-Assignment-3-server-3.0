import dotenv from "dotenv";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { ObjectId } from "mongodb";
import { connectDB, getDb } from "./db";
import { hashPassword, comparePassword } from "./utils/authHelper";
import { TUser } from "./types";

dotenv.config();

const PORT = process.env.PORT || 5000;
const app = express();

const allowedOrigins = [process.env.CLIENT_URL || "http://localhost:3000"];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
  }),
);

app.use(express.json());
app.use(cookieParser());

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
  };
}

function verifyToken(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): any {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized: No token provided",
    });
  }

  const secret =
    process.env.ACCESS_TOKEN_SECRET || "fallback_token_secret_string_pap_key";
  jwt.verify(token, secret, (err: any, decoded: any) => {
    if (err) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized: Invalid token",
      });
    }
    req.user = decoded as { id: string; email: string; role: string };
    next();
  });
}

app.get("/", (req: Request, res: Response) => {
  res.send("Server is up and running!");
});

app.post(
  "/api/auth/signup",
  async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    try {
      const { username, email, password } = req.body;

      if (!username || !email || !password) {
        return res.status(400).json({
          success: false,
          message: "All fields are required",
        });
      }

      const db = getDb();
      const existingUser = await db
        .collection<TUser>("users")
        .findOne({ email });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: "User already exists with this email",
        });
      }

      const hashedPassword = await hashPassword(password);

      const newUser: TUser = {
        username,
        email,
        password: hashedPassword,
        role: "user",
        createdAt: new Date(),
      };

      const result = await db.collection<TUser>("users").insertOne(newUser);

      const secret =
        process.env.ACCESS_TOKEN_SECRET ||
        "fallback_token_secret_string_pap_key";
      const token = jwt.sign(
        { id: result.insertedId.toString(), email, role: "user" },
        secret,
        { expiresIn: "1d" },
      );

      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        maxAge: 24 * 60 * 60 * 1000,
      });

      return res.status(201).json({
        success: true,
        message: "User registered successfully",
        user: {
          id: result.insertedId.toString(),
          username,
          email,
          role: "user",
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

app.post(
  "/api/auth/login",
  async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          success: false,
          message: "Email and password are required",
        });
      }

      const db = getDb();
      const user = await db.collection<TUser>("users").findOne({ email });

      if (!user || !user.password) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password",
        });
      }

      const isPasswordMatch = await comparePassword(password, user.password);

      if (!isPasswordMatch) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password",
        });
      }

      const secret =
        process.env.ACCESS_TOKEN_SECRET ||
        "fallback_token_secret_string_pap_key";
      const token = jwt.sign(
        { id: user._id?.toString(), email: user.email, role: user.role },
        secret,
        { expiresIn: "1d" },
      );

      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        maxAge: 24 * 60 * 60 * 1000,
      });

      return res.status(200).json({
        success: true,
        message: "Logged in successfully",
        user: {
          id: user._id?.toString(),
          username: user.username,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/auth/me",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const userId = req.user?.id;

      if (!userId) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized",
        });
      }

      const user = await db
        .collection<TUser>("users")
        .findOne({ _id: new ObjectId(userId) });

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      return res.status(200).json({
        id: user._id?.toString(),
        name: user.username,
        email: user.email,
        role: user.role,
      });
    } catch (error) {
      next(error);
    }
  },
);

app.use((req: Request, res: Response, next: NextFunction) => {
  res.status(404).json({
    success: false,
    message: `Route not found: ${req.originalUrl}`,
  });
});

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  const statusCode = err.statusCode || err.status || 500;
  res.status(statusCode).json({
    success: false,
    message: err.message || "Internal Server Error",
  });
});

async function startServer() {
  try {
    await connectDB();

    if (process.env.NODE_ENV !== "production") {
      app.listen(PORT, () => {
        console.log(`Server listening on port ${PORT}`);
      });
    }
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();

export { app };
