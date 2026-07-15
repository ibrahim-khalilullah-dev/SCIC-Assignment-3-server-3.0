import dotenv from "dotenv";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import { ObjectId } from "mongodb";
import { connectDB, getDb } from "./db";
import { hashPassword, comparePassword } from "./utils/authHelper";
import { TUser, TProduct } from "./types";

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

async function seedDemoUsers() {
  try {
    const db = getDb();

    const adminEmail = "admin@nextmart.com";
    const userEmail = "user@nextmart.com";

    const adminExists = await db
      .collection<TUser>("users")
      .findOne({ email: adminEmail });
    if (!adminExists) {
      const hashedAdminPassword = await hashPassword("admin123");
      await db.collection<TUser>("users").insertOne({
        username: "Admin Demo",
        email: adminEmail,
        password: hashedAdminPassword,
        role: "admin",
        verifiedReporter: true,
        status: "active",
        createdAt: new Date(),
      });
      console.log("Demo Administrator account seeded successfully.");
    }

    const userExists = await db
      .collection<TUser>("users")
      .findOne({ email: userEmail });
    if (!userExists) {
      const hashedUserPassword = await hashPassword("user123");
      await db.collection<TUser>("users").insertOne({
        username: "Customer Demo",
        email: userEmail,
        password: hashedUserPassword,
        role: "user",
        verifiedReporter: false,
        status: "active",
        createdAt: new Date(),
      });
      console.log("Demo Customer account seeded successfully.");
    }
  } catch (error) {
    console.error("Failed to seed demo users:", error);
  }
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
        verifiedReporter: false,
        status: "active",
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

app.post("/api/auth/logout", (req: Request, res: Response): any => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    path: "/",
  });
  return res.status(200).json({
    success: true,
    message: "Logged out successfully",
  });
});

app.post(
  "/api/auth/google",
  async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    try {
      const { idToken } = req.body;

      if (!idToken) {
        return res.status(400).json({
          success: false,
          message: "Google ID Token is required",
        });
      }

      const googleResponse = await fetch(
        `https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`,
      );

      if (!googleResponse.ok) {
        return res.status(401).json({
          success: false,
          message: "Invalid Google token",
        });
      }

      const payload = (await googleResponse.json()) as any;

      const googleClientId = process.env.GOOGLE_CLIENT_ID;
      if (googleClientId && payload.aud !== googleClientId) {
        return res.status(401).json({
          success: false,
          message: "Client ID verification failed",
        });
      }

      const { email, name } = payload;
      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email not retrieved from Google profile",
        });
      }

      const db = getDb();
      let user = await db.collection<TUser>("users").findOne({ email });

      if (!user) {
        const newUser: TUser = {
          username: name || email.split("@")[0],
          email,
          role: "user",
          verifiedReporter: false,
          status: "active",
          createdAt: new Date(),
        };
        const result = await db.collection<TUser>("users").insertOne(newUser);
        user = { _id: result.insertedId, ...newUser };
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
        message: "Google login successful",
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
  "/api/products",
  async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    try {
      const { search, category, minPrice, maxPrice } = req.query;
      const db = getDb();
      const query: any = {};

      if (search) {
        query.title = { $regex: search as string, $options: "i" };
      }

      if (category) {
        query.category = category as string;
      }

      if (minPrice || maxPrice) {
        query.price = {};
        if (minPrice) query.price.$gte = Number(minPrice);
        if (maxPrice) query.price.$lte = Number(maxPrice);
      }

      const products = await db
        .collection<TProduct>("products")
        .find(query)
        .toArray();

      const formattedProducts = products.map((product) => ({
        id: product._id?.toString(),
        title: product.title,
        description: product.description,
        category: product.category,
        image: product.image,
        price: product.price,
        rating: product.rating,
        stock: product.stock,
        featured: product.featured,
        sellerId: product.sellerId,
        sellerName: product.sellerName,
        sellerEmail: product.sellerEmail,
        status: product.status,
      }));

      return res.status(200).json(formattedProducts);
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/products/:id",
  async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    try {
      const id = req.params.id as string;
      const db = getDb();

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid product identifier",
        });
      }

      const product = await db
        .collection<TProduct>("products")
        .findOne({ _id: new ObjectId(id) });

      if (!product) {
        return res.status(404).json({
          success: false,
          message: "Product not found",
        });
      }

      return res.status(200).json({
        id: product._id?.toString(),
        title: product.title,
        description: product.description,
        category: product.category,
        image: product.image,
        price: product.price,
        rating: product.rating,
        stock: product.stock,
        featured: product.featured,
        sellerId: product.sellerId,
        sellerName: product.sellerName,
        sellerEmail: product.sellerEmail,
        status: product.status,
      });
    } catch (error) {
      next(error);
    }
  },
);

app.post(
  "/api/products",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const {
        title,
        description,
        category,
        image,
        price,
        rating,
        stock,
        featured,
      } = req.body;

      if (!title || !category || !price || !image) {
        return res.status(400).json({
          success: false,
          message: "Title, category, price, and image are required",
        });
      }

      const newProduct: TProduct = {
        title,
        description: description || "",
        category,
        image,
        price: Number(price),
        rating: Number(rating) || 0,
        stock: Number(stock) || 0,
        featured: Boolean(featured),
        sellerId: req.user?.id || "",
        sellerName: req.user?.email.split("@")[0] || "",
        sellerEmail: req.user?.email || "",
        status: "Available",
        createdAt: new Date(),
      };

      const result = await db
        .collection<TProduct>("products")
        .insertOne(newProduct);

      return res.status(201).json({
        success: true,
        message: "Product created successfully",
        id: result.insertedId.toString(),
      });
    } catch (error) {
      next(error);
    }
  },
);

app.put(
  "/api/products/:id",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const id = req.params.id as string;
      const db = getDb();

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid product identifier",
        });
      }

      const updates = { ...req.body };
      delete updates._id;
      delete updates.id;

      if (updates.price) updates.price = Number(updates.price);
      if (updates.rating) updates.rating = Number(updates.rating);
      if (updates.stock) updates.stock = Number(updates.stock);
      if (updates.featured !== undefined)
        updates.featured = Boolean(updates.featured);

      const result = await db
        .collection<TProduct>("products")
        .updateOne({ _id: new ObjectId(id) }, { $set: updates });

      if (result.matchedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Product not found",
        });
      }

      return res.status(200).json({
        success: true,
        message: "Product updated successfully",
      });
    } catch (error) {
      next(error);
    }
  },
);

app.delete(
  "/api/products/:id",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const id = req.params.id as string;
      const db = getDb();

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid product identifier",
        });
      }

      const result = await db.collection<TProduct>("products").deleteOne({
        _id: new ObjectId(id),
      });

      if (result.deletedCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Product not found",
        });
      }

      return res.status(200).json({
        success: true,
        message: "Product deleted successfully",
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
    await seedDemoUsers();

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
