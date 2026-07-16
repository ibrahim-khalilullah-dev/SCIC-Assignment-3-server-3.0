"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.connectDB = connectDB;
exports.getDb = getDb;
const dotenv_1 = __importDefault(require("dotenv"));
const mongodb_1 = require("mongodb");
dotenv_1.default.config();
const uri = process.env.MONGO_URI;
if (!uri) {
    throw new Error("MONGO_URI is not defined in environment variables");
}
const client = new mongodb_1.MongoClient(uri, {
    serverApi: {
        version: mongodb_1.ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});
let db;
async function connectDB() {
    if (!db) {
        await client.connect();
        db = client.db("NextMart");
    }
}
function getDb() {
    if (!db) {
        throw new Error("Database not initialized. Call connectDB first.");
    }
    return db;
}
