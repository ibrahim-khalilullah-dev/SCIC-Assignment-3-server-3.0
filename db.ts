import { MongoClient, Db } from "mongodb";

const uri = process.env.MONGO_URI;
if (!uri) {
  throw new Error("MONGO_URI is not defined in environment variables");
}

const client = new MongoClient(uri);
let db: Db;

export async function connectDB(): Promise<void> {
  try {
    await client.connect();
    db = client.db("NextMart");
    console.log("Database connected successfully to NextMart");
  } catch (error) {
    console.error("Database connection failed:", error);
    throw error;
  }
}

export function getDb(): Db {
  if (!db) {
    throw new Error("Database not initialized. Call connectDB first.");
  }
  return db;
}
