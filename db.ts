import dotenv from "dotenv";
import { MongoClient, Db } from "mongodb";

dotenv.config();

const uri = process.env.MONGO_URI;
if (!uri) {
  throw new Error("MONGO_URI is not defined in environment variables");
}

const client = new MongoClient(uri);
let db: Db;

export async function connectDB(): Promise<void> {
  if (!db) {
    await client.connect();
    db = client.db("NextMart");
  }
}

export function getDb(): Db {
  if (!db) {
    throw new Error("Database not initialized. Call connectDB first.");
  }
  return db;
}
