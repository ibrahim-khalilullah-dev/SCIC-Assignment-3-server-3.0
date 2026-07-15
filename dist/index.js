"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.app = void 0;
const dotenv_1 = __importDefault(require("dotenv"));
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const mongodb_1 = require("mongodb");
const stripe_1 = __importDefault(require("stripe"));
const db_1 = require("./db");
const authHelper_1 = require("./utils/authHelper");
dotenv_1.default.config();
const PORT = process.env.PORT || 5000;
const app = (0, express_1.default)();
exports.app = app;
const stripe = new stripe_1.default(process.env.STRIPE_SECRET_KEY || "sk_test_mock_key_for_vercel_startup_pass");
const allowedOrigins = [process.env.CLIENT_URL || "http://localhost:3000"];
app.use((0, cors_1.default)({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        }
        else {
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
}));
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
function verifyToken(req, res, next) {
    const token = req.cookies?.token;
    if (!token) {
        return res.status(401).json({
            success: false,
            message: "Unauthorized: No token provided",
        });
    }
    const secret = process.env.ACCESS_TOKEN_SECRET || "fallback_token_secret_string_pap_key";
    jsonwebtoken_1.default.verify(token, secret, async (err, decoded) => {
        if (err) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized: Invalid token",
            });
        }
        try {
            const db = (0, db_1.getDb)();
            const user = await db
                .collection("users")
                .findOne({ _id: new mongodb_1.ObjectId(decoded.id) });
            if (!user) {
                return res.status(401).json({
                    success: false,
                    message: "Unauthorized: User not found",
                });
            }
            if (user.status === "banned") {
                return res.status(403).json({
                    success: false,
                    message: "Your account has been banned.",
                });
            }
            req.user = {
                id: user._id?.toString() || "",
                email: user.email,
                role: user.role,
            };
            next();
        }
        catch (error) {
            next(error);
        }
    });
}
function verifyReporter(req, res, next) {
    if (req.user?.role !== "reporter" && req.user?.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Forbidden access. Reporter privileges required.",
        });
    }
    next();
}
function verifyAdmin(req, res, next) {
    if (req.user?.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Forbidden access. Administrator privileges required.",
        });
    }
    next();
}
async function seedDemoUsers() {
    try {
        const db = (0, db_1.getDb)();
        const adminEmail = "admin@nextmart.com";
        const userEmail = "user@nextmart.com";
        const adminExists = await db
            .collection("users")
            .findOne({ email: adminEmail });
        if (!adminExists) {
            const hashedAdminPassword = await (0, authHelper_1.hashPassword)("admin123");
            await db.collection("users").insertOne({
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
            .collection("users")
            .findOne({ email: userEmail });
        if (!userExists) {
            const hashedUserPassword = await (0, authHelper_1.hashPassword)("user123");
            await db.collection("users").insertOne({
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
    }
    catch (error) {
        console.error("Failed to seed demo users:", error);
    }
}
app.get("/", (req, res) => {
    res.send("Server is up and running!");
});
app.post("/api/auth/signup", async (req, res, next) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required",
            });
        }
        const db = (0, db_1.getDb)();
        const existingUser = await db
            .collection("users")
            .findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: "User already exists with this email",
            });
        }
        const hashedPassword = await (0, authHelper_1.hashPassword)(password);
        const newUser = {
            username,
            email,
            password: hashedPassword,
            role: "user",
            verifiedReporter: false,
            status: "active",
            createdAt: new Date(),
        };
        const result = await db.collection("users").insertOne(newUser);
        const secret = process.env.ACCESS_TOKEN_SECRET ||
            "fallback_token_secret_string_pap_key";
        const token = jsonwebtoken_1.default.sign({ id: result.insertedId.toString(), email, role: "user" }, secret, { expiresIn: "1d" });
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
    }
    catch (error) {
        next(error);
    }
});
app.post("/api/auth/login", async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required",
            });
        }
        const db = (0, db_1.getDb)();
        const user = await db.collection("users").findOne({ email });
        if (!user || !user.password) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password",
            });
        }
        const isPasswordMatch = await (0, authHelper_1.comparePassword)(password, user.password);
        if (!isPasswordMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password",
            });
        }
        const secret = process.env.ACCESS_TOKEN_SECRET ||
            "fallback_token_secret_string_pap_key";
        const token = jsonwebtoken_1.default.sign({ id: user._id?.toString(), email: user.email, role: user.role }, secret, { expiresIn: "1d" });
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
    }
    catch (error) {
        next(error);
    }
});
app.get("/api/auth/me", verifyToken, async (req, res, next) => {
    try {
        const db = (0, db_1.getDb)();
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }
        const user = await db
            .collection("users")
            .findOne({ _id: new mongodb_1.ObjectId(userId) });
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
    }
    catch (error) {
        next(error);
    }
});
app.post("/api/auth/logout", (req, res) => {
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
app.post("/api/auth/google", async (req, res, next) => {
    try {
        const { idToken } = req.body;
        if (!idToken) {
            return res.status(400).json({
                success: false,
                message: "Google ID Token is required",
            });
        }
        const googleResponse = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
        if (!googleResponse.ok) {
            return res.status(401).json({
                success: false,
                message: "Invalid Google token",
            });
        }
        const payload = (await googleResponse.json());
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
        const db = (0, db_1.getDb)();
        let user = await db.collection("users").findOne({ email });
        if (!user) {
            const newUser = {
                username: name || email.split("@")[0],
                email,
                role: "user",
                verifiedReporter: false,
                status: "active",
                createdAt: new Date(),
            };
            const result = await db.collection("users").insertOne(newUser);
            user = { _id: result.insertedId, ...newUser };
        }
        const secret = process.env.ACCESS_TOKEN_SECRET ||
            "fallback_token_secret_string_pap_key";
        const token = jsonwebtoken_1.default.sign({ id: user._id?.toString(), email: user.email, role: user.role }, secret, { expiresIn: "1d" });
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
    }
    catch (error) {
        next(error);
    }
});
app.get("/api/products", async (req, res, next) => {
    try {
        const { search, category, minPrice, maxPrice } = req.query;
        const db = (0, db_1.getDb)();
        const query = {};
        if (search) {
            query.title = { $regex: search, $options: "i" };
        }
        if (category) {
            query.category = category;
        }
        if (minPrice || maxPrice) {
            query.price = {};
            if (minPrice)
                query.price.$gte = Number(minPrice);
            if (maxPrice)
                query.price.$lte = Number(maxPrice);
        }
        const products = await db
            .collection("products")
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
    }
    catch (error) {
        next(error);
    }
});
app.get("/api/products/:id", async (req, res, next) => {
    try {
        const id = req.params.id;
        const db = (0, db_1.getDb)();
        if (!mongodb_1.ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid product identifier",
            });
        }
        const product = await db
            .collection("products")
            .findOne({ _id: new mongodb_1.ObjectId(id) });
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
    }
    catch (error) {
        next(error);
    }
});
app.post("/api/products", verifyToken, async (req, res, next) => {
    try {
        const db = (0, db_1.getDb)();
        const { title, description, category, image, price, rating, stock, featured, } = req.body;
        if (!title || !category || !price || !image) {
            return res.status(400).json({
                success: false,
                message: "Title, category, price, and image are required",
            });
        }
        const newProduct = {
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
            .collection("products")
            .insertOne(newProduct);
        return res.status(201).json({
            success: true,
            message: "Product created successfully",
            id: result.insertedId.toString(),
        });
    }
    catch (error) {
        next(error);
    }
});
app.put("/api/products/:id", verifyToken, async (req, res, next) => {
    try {
        const id = req.params.id;
        const db = (0, db_1.getDb)();
        if (!mongodb_1.ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid product identifier",
            });
        }
        const updates = { ...req.body };
        delete updates._id;
        delete updates.id;
        if (updates.price)
            updates.price = Number(updates.price);
        if (updates.rating)
            updates.rating = Number(updates.rating);
        if (updates.stock)
            updates.stock = Number(updates.stock);
        if (updates.featured !== undefined)
            updates.featured = Boolean(updates.featured);
        const result = await db
            .collection("products")
            .updateOne({ _id: new mongodb_1.ObjectId(id) }, { $set: updates });
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
    }
    catch (error) {
        next(error);
    }
});
app.delete("/api/products/:id", verifyToken, async (req, res, next) => {
    try {
        const id = req.params.id;
        const db = (0, db_1.getDb)();
        if (!mongodb_1.ObjectId.isValid(id)) {
            return res.status(400).json({
                success: false,
                message: "Invalid product identifier",
            });
        }
        const result = await db.collection("products").deleteOne({
            _id: new mongodb_1.ObjectId(id),
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
    }
    catch (error) {
        next(error);
    }
});
app.post("/api/create-checkout-session", verifyToken, async (req, res, next) => {
    try {
        const { type, productId, price } = req.body;
        const user = req.user;
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized access",
            });
        }
        const origin = req.headers.origin || "http://localhost:3000";
        let lineItems = [];
        let metadata = {};
        let successUrl = "";
        let cancelUrl = "";
        if (type === "publishing fee") {
            lineItems = [
                {
                    price_data: {
                        currency: "usd",
                        product_data: {
                            name: "Vendor Lifetime Verification Fee",
                            description: "One-time security license to activate product publication desk",
                        },
                        unit_amount: Math.round(parseFloat(price) * 100),
                    },
                    quantity: 1,
                },
            ];
            metadata = {
                type: "publishing fee",
                buyerEmail: user.email,
            };
            successUrl = `${origin}/dashboard/reporter/success?session_id={CHECKOUT_SESSION_ID}`;
            cancelUrl = `${origin}/dashboard/reporter`;
        }
        else if (type === "purchase" && productId) {
            const db = (0, db_1.getDb)();
            const product = await db
                .collection("products")
                .findOne({ _id: new mongodb_1.ObjectId(productId) });
            if (!product) {
                return res.status(404).json({
                    success: false,
                    message: "Target product not found",
                });
            }
            lineItems = [
                {
                    price_data: {
                        currency: "usd",
                        product_data: {
                            name: product.title,
                            description: `Standard goods delivered by verified vendor: ${product.sellerName}`,
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
            successUrl = `${origin}/products/success?session_id={CHECKOUT_SESSION_ID}&product_id=${product._id?.toString()}`;
            cancelUrl = `${origin}/products/${product._id?.toString()}`;
        }
        else {
            return res.status(400).json({
                success: false,
                message: "Invalid session checkout parameters",
            });
        }
        const session = await stripe.checkout.sessions.create({
            customer_email: user.email,
            line_items: lineItems,
            mode: "payment",
            metadata: metadata,
            success_url: successUrl,
            cancel_url: cancelUrl,
        });
        return res.status(200).json({
            id: session.id,
            url: session.url,
        });
    }
    catch (error) {
        next(error);
    }
});
app.get("/api/verify-payment", verifyToken, async (req, res, next) => {
    try {
        const { session_id } = req.query;
        if (!session_id || typeof session_id !== "string") {
            return res.status(400).json({
                success: false,
                message: "Stripe payment session identifier required",
            });
        }
        const db = (0, db_1.getDb)();
        const session = await stripe.checkout.sessions.retrieve(session_id);
        if (session.payment_status !== "paid") {
            return res.status(400).json({
                success: false,
                message: "Target checkout payment not finalized",
            });
        }
        const existingTx = await db
            .collection("transactions")
            .findOne({ transactionId: session_id });
        if (existingTx) {
            return res.status(200).json({
                success: true,
                alreadyProcessed: true,
                transaction: existingTx,
            });
        }
        const metadata = (session.metadata || {});
        const type = metadata.type;
        const buyerEmail = metadata.buyerEmail;
        const productId = metadata.productId;
        const sellerEmail = metadata.sellerEmail;
        const amount = session.amount_total ? session.amount_total / 100 : 0;
        const txRecord = {
            transactionId: session_id,
            type,
            productId: productId ? new mongodb_1.ObjectId(productId) : null,
            buyerEmail,
            sellerEmail: sellerEmail || null,
            amount,
            createdAt: new Date(),
        };
        await db.collection("transactions").insertOne(txRecord);
        if (type === "publishing fee") {
            await db
                .collection("users")
                .updateOne({ email: buyerEmail }, { $set: { verifiedReporter: true, role: "reporter" } });
        }
        else if (type === "purchase" && productId) {
            const product = await db
                .collection("products")
                .findOne({ _id: new mongodb_1.ObjectId(productId) });
            if (product) {
                const newStock = Math.max(0, product.stock - 1);
                const newStatus = newStock === 0 ? "Sold" : "Available";
                await db
                    .collection("products")
                    .updateOne({ _id: new mongodb_1.ObjectId(productId) }, { $set: { stock: newStock, status: newStatus } });
            }
        }
        return res.status(200).json({
            success: true,
            transaction: txRecord,
        });
    }
    catch (error) {
        next(error);
    }
});
app.post("/api/bookmarks", verifyToken, async (req, res, next) => {
    try {
        const { productId } = req.body;
        const userId = req.user?.id;
        if (!productId) {
            return res.status(400).json({
                success: false,
                message: "Product identifier required",
            });
        }
        if (!userId) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }
        const db = (0, db_1.getDb)();
        const existingBookmark = await db
            .collection("bookmarks")
            .findOne({ userId, productId });
        if (existingBookmark) {
            return res.status(400).json({
                success: false,
                message: "Product is already wishlisted",
            });
        }
        const product = await db
            .collection("products")
            .findOne({ _id: new mongodb_1.ObjectId(productId) });
        if (!product) {
            return res.status(404).json({
                success: false,
                message: "Catalog product not found",
            });
        }
        const bookmark = {
            userId,
            productId,
            productTitle: product.title,
            productImage: product.image,
            productPrice: product.price,
            productCategory: product.category,
            productSeller: product.sellerName,
            createdAt: new Date(),
        };
        const result = await db
            .collection("bookmarks")
            .insertOne(bookmark);
        return res.status(201).json({
            success: true,
            id: result.insertedId.toString(),
        });
    }
    catch (error) {
        next(error);
    }
});
app.get("/api/bookmarks", verifyToken, async (req, res, next) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }
        const db = (0, db_1.getDb)();
        const bookmarks = await db
            .collection("bookmarks")
            .find({ userId })
            .toArray();
        return res.status(200).json(bookmarks);
    }
    catch (error) {
        next(error);
    }
});
app.delete("/api/bookmarks/:productId", verifyToken, async (req, res, next) => {
    try {
        const productId = req.params.productId;
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({
                success: false,
                message: "Unauthorized",
            });
        }
        const db = (0, db_1.getDb)();
        const result = await db
            .collection("bookmarks")
            .deleteOne({ userId, productId });
        return res.status(200).json({
            success: true,
            deletedCount: result.deletedCount,
        });
    }
    catch (error) {
        next(error);
    }
});
app.use((req, res, next) => {
    res.status(404).json({
        success: false,
        message: `Route not found: ${req.originalUrl}`,
    });
});
app.use((err, req, res, next) => {
    const statusCode = err.statusCode || err.status || 500;
    res.status(statusCode).json({
        success: false,
        message: err.message || "Internal Server Error",
    });
});
async function startServer() {
    try {
        await (0, db_1.connectDB)();
        await seedDemoUsers();
        if (process.env.NODE_ENV !== "production") {
            app.listen(PORT, () => {
                console.log(`Server listening on port ${PORT}`);
            });
        }
    }
    catch (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
}
startServer();
