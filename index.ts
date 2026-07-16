import dotenv from "dotenv";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { ObjectId } from "mongodb";
import Stripe from "stripe";
import { connectDB, getDb } from "./db";
import { TUser, TProduct } from "./types";

dotenv.config();

const PORT = process.env.PORT || 5000;
const app = express();

const stripe = new Stripe(
  process.env.STRIPE_SECRET_KEY || "sk_test_mock_key_for_vercel_startup_pass",
);

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

app.use(async (req: Request, res: Response, next: NextFunction) => {
  try {
    await connectDB();
    next();
  } catch (error) {
    next(error);
  }
});

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
    verifiedWriter?: boolean;
  };
}

async function verifyToken(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): Promise<any> {
  const authHeader = req.headers?.authorization;
  let token = authHeader?.split(" ")[1];

  if (!token) {
    token =
      req.cookies?.["better-auth.session_token"] ||
      req.cookies?.["__Secure-better-auth.session_token"];
  }

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Unauthorized access" });
  }

  try {
    const db = getDb();
    const session = await db.collection("session").findOne({ token: token });
    if (!session) {
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized access" });
    }

    const userId = session.userId;
    const userQuery = ObjectId.isValid(userId)
      ? { _id: new ObjectId(userId) }
      : { _id: userId };
    const user = await db.collection<TUser>("user").findOne(userQuery as any);

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Unauthorized access" });
    }

    if (user.status === "banned") {
      return res
        .status(403)
        .json({ success: false, message: "Your account has been banned." });
    }

    req.user = {
      id: user._id?.toString() || (user as any).id || "",
      email: user.email,
      role: user.role || (user as any).userRole || "user",
      verifiedWriter:
        user.verifiedWriter || (user as any).verifiedWriter || false,
    };
    next();
  } catch {
    return res
      .status(401)
      .json({ success: false, message: "Unauthorized access" });
  }
}

function verifyReporter(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): any {
  if (req.user?.role !== "reporter" && req.user?.role !== "admin") {
    return res
      .status(403)
      .json({ success: false, message: "Reporter privileges required" });
  }
  if (req.user?.role === "reporter" && !req.user?.verifiedWriter) {
    return res.status(403).json({
      success: false,
      message: "Verification required. Please complete your fee payment.",
    });
  }
  next();
}

function verifyAdmin(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): any {
  if (req.user?.role !== "admin") {
    return res
      .status(403)
      .json({ success: false, message: "Admin privileges required" });
  }
  next();
}

const mapProduct = (p: any) => ({
  id: p._id?.toString(),
  title: p.title,
  description: p.description,
  category: p.category,
  image: p.image,
  price: p.price,
  rating: p.rating,
  stock: p.stock,
  featured: p.featured,
  sellerId: p.sellerId,
  sellerName: p.sellerName,
  sellerEmail: p.sellerEmail,
  status: p.status,
});

app.get("/", (req: Request, res: Response) => {
  res.send("Server is up and running!");
});

app.get(
  "/api/products",
  async (req: Request, res: Response, next: NextFunction): Promise<any> => {
    try {
      const { search, category, minPrice, maxPrice } = req.query;
      const db = getDb();
      const query: any = {};

      if (search) query.title = { $regex: search as string, $options: "i" };
      if (category) query.category = category as string;
      if (minPrice || maxPrice) {
        query.price = {};
        if (minPrice) query.price.$gte = Number(minPrice);
        if (maxPrice) query.price.$lte = Number(maxPrice);
      }

      const products = await db
        .collection<TProduct>("products")
        .find(query)
        .toArray();
      return res.status(200).json(products.map(mapProduct));
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
      if (!ObjectId.isValid(id))
        return res.status(400).json({ success: false });

      const db = getDb();
      const p = await db
        .collection<TProduct>("products")
        .findOne({ _id: new ObjectId(id) });
      return p
        ? res.status(200).json(mapProduct(p))
        : res.status(404).json({ success: false });
    } catch (error) {
      next(error);
    }
  },
);

app.post(
  "/api/products",
  verifyToken,
  verifyReporter,
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
      if (!title || !category || !price || !image)
        return res.status(400).json({ success: false });

      const result = await db.collection<TProduct>("products").insertOne({
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
      });

      return res
        .status(201)
        .json({ success: true, id: result.insertedId.toString() });
    } catch (error) {
      next(error);
    }
  },
);

app.put(
  "/api/products/:id",
  verifyToken,
  verifyReporter,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const id = req.params.id as string;
      if (!ObjectId.isValid(id))
        return res.status(400).json({ success: false });

      const db = getDb();
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
      if (result.matchedCount === 0)
        return res.status(404).json({ success: false });

      return res.status(200).json({ success: true });
    } catch (error) {
      next(error);
    }
  },
);

app.delete(
  "/api/products/:id",
  verifyToken,
  verifyReporter,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const id = req.params.id as string;
      if (!ObjectId.isValid(id))
        return res.status(400).json({ success: false });

      const db = getDb();
      const result = await db
        .collection<TProduct>("products")
        .deleteOne({ _id: new ObjectId(id) });
      if (result.deletedCount === 0)
        return res.status(404).json({ success: false });

      return res.status(200).json({ success: true });
    } catch (error) {
      next(error);
    }
  },
);

app.post(
  "/api/create-checkout-session",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const { type, productId, price } = req.body;
      const user = req.user;
      if (!user) return res.status(401).json({ success: false });

      const origin = req.headers.origin || "http://localhost:3000";
      let lineItems: any[] = [];
      let metadata: any = {};
      let successUrl = "";
      let cancelUrl = "";

      if (type === "publishing fee") {
        lineItems = [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: "Vendor Activation",
                description: "One-time vendor workspace registration fee",
              },
              unit_amount: Math.round(parseFloat(price) * 100),
            },
            quantity: 1,
          },
        ];
        metadata = { type: "publishing fee", buyerEmail: user.email };
        successUrl =
          origin +
          "/dashboard/reporter/success?session_id={CHECKOUT_SESSION_ID}";
        cancelUrl = origin + "/dashboard/reporter";
      } else if (type === "purchase" && productId) {
        const db = getDb();
        const product = await db
          .collection<TProduct>("products")
          .findOne({ _id: new ObjectId(productId) });
        if (!product) return res.status(404).json({ success: false });

        lineItems = [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: product.title,
                description: "Goods from seller: " + product.sellerName,
              },
              unit_amount: Math.round(product.price * 100),
            },
            quantity: 1,
          },
        ];

        metadata = {
          type: "purchase",
          productId: product._id?.toString() || "",
          buyerEmail: user.email,
          sellerEmail: product.sellerEmail || "",
          amount: product.price.toString(),
        };
        successUrl =
          origin +
          "/products/success?session_id={CHECKOUT_SESSION_ID}&product_id=" +
          product._id?.toString();
        cancelUrl = origin + "/products/" + product._id?.toString();
      } else {
        return res
          .status(400)
          .json({ success: false, message: "Invalid parameters" });
      }

      const session = await stripe.checkout.sessions.create({
        customer_email: user.email,
        line_items: lineItems,
        mode: "payment",
        metadata: metadata,
        success_url: successUrl,
        cancel_url: cancelUrl,
      });

      return res.status(200).json({ id: session.id, url: session.url });
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/verify-payment",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const { session_id } = req.query;
      if (!session_id || typeof session_id !== "string")
        return res
          .status(400)
          .json({ success: false, message: "Session ID required" });

      const db = getDb();
      const session = await stripe.checkout.sessions.retrieve(session_id);
      if (session.payment_status !== "paid")
        return res.status(400).json({ success: false, message: "Unpaid" });

      const existingTx = await db
        .collection("transactions")
        .findOne({ transactionId: session_id });
      if (existingTx)
        return res.status(200).json({
          success: true,
          alreadyProcessed: true,
          transaction: existingTx,
        });

      const metadata = (session.metadata || {}) as any;
      const type = metadata.type;
      const buyerEmail = metadata.buyerEmail;
      const productId = metadata.productId;
      const sellerEmail = metadata.sellerEmail;
      const amount = session.amount_total ? session.amount_total / 100 : 0;

      const txRecord = {
        transactionId: session_id,
        type,
        productId: productId ? new ObjectId(productId) : null,
        buyerEmail,
        sellerEmail: sellerEmail || null,
        amount,
        createdAt: new Date(),
      };

      await db.collection("transactions").insertOne(txRecord);

      if (type === "publishing fee") {
        await db
          .collection("user")
          .updateOne({ email: buyerEmail }, { $set: { verifiedWriter: true } });
      } else if (type === "purchase" && productId) {
        const product = await db
          .collection<TProduct>("products")
          .findOne({ _id: new ObjectId(productId) });
        if (product) {
          const newStock = Math.max(0, product.stock - 1);
          const newStatus = newStock === 0 ? "Sold" : "Available";
          await db
            .collection<TProduct>("products")
            .updateOne(
              { _id: new ObjectId(productId) },
              { $set: { stock: newStock, status: newStatus } },
            );
        }
      }

      return res.status(200).json({ success: true, transaction: txRecord });
    } catch (error) {
      next(error);
    }
  },
);

app.patch(
  "/api/users/profile",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const { name, image } = req.body;
      if (!name) {
        return res
          .status(400)
          .json({ success: false, message: "Name is required" });
      }

      const db = getDb();
      const userId = req.user?.id;
      const query = ObjectId.isValid(userId || "")
        ? { _id: new ObjectId(userId) }
        : { _id: userId };

      await db.collection("user").updateOne(query as any, {
        $set: { name, image },
      });

      return res
        .status(200)
        .json({ success: true, message: "Profile updated successfully" });
    } catch (error) {
      next(error);
    }
  },
);

app.post(
  "/api/bookmarks",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const { productId } = req.body;
      const userId = req.user?.id;
      if (!productId || !userId)
        return res
          .status(400)
          .json({ success: false, message: "Parameters missing" });

      const db = getDb();
      const existingBookmark = await db
        .collection("bookmarks")
        .findOne({ userId, productId });
      if (existingBookmark)
        return res
          .status(400)
          .json({ success: false, message: "Already saved" });

      const product = await db
        .collection<TProduct>("products")
        .findOne({ _id: new ObjectId(productId) });
      if (!product)
        return res.status(404).json({ success: false, message: "Not found" });

      const result = await db.collection("bookmarks").insertOne({
        userId,
        productId,
        productTitle: product.title,
        productImage: product.image,
        productPrice: product.price,
        productCategory: product.category,
        productSeller: product.sellerName,
        createdAt: new Date(),
      });

      return res
        .status(201)
        .json({ success: true, id: result.insertedId.toString() });
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/bookmarks",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const userId = req.user?.id;
      if (!userId)
        return res
          .status(401)
          .json({ success: false, message: "Unauthorized" });

      const db = getDb();
      const bookmarks = await db
        .collection("bookmarks")
        .find({ userId })
        .toArray();
      return res.status(200).json(bookmarks);
    } catch (error) {
      next(error);
    }
  },
);

app.delete(
  "/api/bookmarks/:productId",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const productId = req.params.productId as string;
      const userId = req.user?.id;
      if (!userId)
        return res
          .status(401)
          .json({ success: false, message: "Unauthorized" });

      const db = getDb();
      const result = await db
        .collection("bookmarks")
        .deleteOne({ userId, productId });
      return res
        .status(200)
        .json({ success: true, deletedCount: result.deletedCount });
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/reporter/products",
  verifyToken,
  verifyReporter,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const products = await db
        .collection<TProduct>("products")
        .find({ sellerId: req.user?.id })
        .toArray();
      return res.status(200).json(products.map(mapProduct));
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/reporter/sales",
  verifyToken,
  verifyReporter,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const sales = await db
        .collection("transactions")
        .find({ sellerEmail: req.user?.email, type: "purchase" })
        .sort({ createdAt: -1 })
        .toArray();
      return res.status(200).json(sales);
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/user/purchases",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const purchases = await db
        .collection("transactions")
        .find({ buyerEmail: req.user?.email, type: "purchase" })
        .sort({ createdAt: -1 })
        .toArray();
      return res.status(200).json(purchases);
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/user/purchased-products",
  verifyToken,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const purchases = await db
        .collection("transactions")
        .find({ buyerEmail: req.user?.email, type: "purchase" })
        .toArray();
      const productIds = purchases
        .filter((p: any) => p.productId)
        .map((p: any) => new ObjectId(p.productId.toString()));

      if (productIds.length === 0) return res.status(200).json([]);

      const products = await db
        .collection<TProduct>("products")
        .find({ _id: { $in: productIds } })
        .toArray();
      return res.status(200).json(products.map(mapProduct));
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/admin/users",
  verifyToken,
  verifyAdmin,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const users = await db.collection<TUser>("user").find().toArray();
      return res.status(200).json(
        users.map((u) => ({
          id: u._id?.toString() || (u as any).id || "",
          name: u.username || (u as any).name || "",
          email: u.email,
          role: u.role || (u as any).userRole || "user",
          status: u.status,
          verifiedReporter: u.verifiedWriter,
        })),
      );
    } catch (error) {
      next(error);
    }
  },
);

app.patch(
  "/api/admin/users/:id/role",
  verifyToken,
  verifyAdmin,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const id = req.params.id as string;
      const { role } = req.body;
      const query = ObjectId.isValid(id)
        ? { _id: new ObjectId(id) }
        : { _id: id };
      const db = getDb();
      const result = await db
        .collection<TUser>("user")
        .updateOne(query as any, { $set: { role, userRole: role } });
      return res
        .status(200)
        .json({ success: true, matchedCount: result.matchedCount });
    } catch (error) {
      next(error);
    }
  },
);

app.patch(
  "/api/admin/users/:id/ban",
  verifyToken,
  verifyAdmin,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const id = req.params.id as string;
      const query = ObjectId.isValid(id)
        ? { _id: new ObjectId(id) }
        : { _id: id };
      const db = getDb();
      const result = await db
        .collection<TUser>("user")
        .updateOne(query as any, { $set: { status: "banned" } });
      return res
        .status(200)
        .json({ success: true, matchedCount: result.matchedCount });
    } catch (error) {
      next(error);
    }
  },
);

app.patch(
  "/api/admin/users/:id/unban",
  verifyToken,
  verifyAdmin,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const id = req.params.id as string;
      const query = ObjectId.isValid(id)
        ? { _id: new ObjectId(id) }
        : { _id: id };
      const db = getDb();
      const result = await db
        .collection<TUser>("user")
        .updateOne(query as any, { $set: { status: "active" } });
      return res
        .status(200)
        .json({ success: true, matchedCount: result.matchedCount });
    } catch (error) {
      next(error);
    }
  },
);

app.delete(
  "/api/admin/users/:id",
  verifyToken,
  verifyAdmin,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const id = req.params.id as string;
      const query = ObjectId.isValid(id)
        ? { _id: new ObjectId(id) }
        : { _id: id };
      const db = getDb();
      const result = await db.collection<TUser>("user").deleteOne(query as any);
      return res
        .status(200)
        .json({ success: true, deletedCount: result.deletedCount });
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/admin/products",
  verifyToken,
  verifyAdmin,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const products = await db
        .collection<TProduct>("products")
        .find()
        .sort({ createdAt: -1 })
        .toArray();
      return res.status(200).json(
        products.map((p) => ({
          id: p._id?.toString(),
          title: p.title,
          description: p.description,
          category: p.category,
          image: p.image,
          price: p.price,
          rating: p.rating,
          stock: p.stock,
          featured: p.featured,
          sellerId: p.sellerId,
          sellerName: p.sellerName,
          sellerEmail: p.sellerEmail,
          status: p.status,
        })),
      );
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/admin/transactions",
  verifyToken,
  verifyAdmin,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const transactions = await db
        .collection("transactions")
        .find()
        .sort({ createdAt: -1 })
        .toArray();
      return res.status(200).json(transactions);
    } catch (error) {
      next(error);
    }
  },
);

app.get(
  "/api/admin/analytics",
  verifyToken,
  verifyAdmin,
  async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ): Promise<any> => {
    try {
      const db = getDb();
      const totalUsers = await db.collection("user").countDocuments();
      const totalWriters = await db
        .collection("user")
        .countDocuments({ role: "reporter" });
      const totalEbooks = await db.collection("products").countDocuments();
      const totalSold = await db
        .collection("products")
        .countDocuments({ status: "Sold" });

      const revenueAggr = await db
        .collection("transactions")
        .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
        .toArray();
      const totalRevenue = revenueAggr[0]?.total || 0;

      const genreAggr = await db
        .collection("products")
        .aggregate([{ $group: { _id: "$category", count: { $sum: 1 } } }])
        .toArray();

      const salesAggr = await db
        .collection("transactions")
        .aggregate([
          { $match: { type: "purchase" } },
          {
            $group: {
              _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } },
              totalSales: { $sum: "$amount" },
            },
          },
          { $sort: { _id: 1 } },
        ])
        .toArray();

      return res.status(200).json({
        totalUsers,
        totalWriters,
        totalEbooks,
        totalSold,
        totalRevenue,
        genreAnalytics: genreAggr,
        monthlySales: salesAggr,
      });
    } catch (error) {
      next(error);
    }
  },
);

app.use((req: Request, res: Response, next: NextFunction) => {
  res.status(404).json({ success: false, message: "Route not found" });
});

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  const statusCode = err.statusCode || err.status || 500;
  res
    .status(statusCode)
    .json({ success: false, message: err.message || "Internal Server Error" });
});

async function startServer() {
  try {
    await connectDB();
    if (process.env.NODE_ENV !== "production") {
      app.listen(PORT, () => {
        console.log("Server listening on port " + PORT);
      });
    }
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();

export default app;
