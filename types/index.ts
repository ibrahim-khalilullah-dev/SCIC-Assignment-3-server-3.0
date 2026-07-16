import { ObjectId } from "mongodb";

export interface TUser {
  _id?: ObjectId;
  username: string;
  email: string;
  password?: string;
  role: "user" | "reporter" | "admin";
  verifiedWriter: boolean;
  status: "active" | "banned";
  image?: string;
  createdAt: Date;
}

export interface TProduct {
  _id?: ObjectId;
  title: string;
  description: string;
  category: string;
  image: string;
  price: number;
  rating: number;
  stock: number;
  featured: boolean;
  sellerId: string;
  sellerName: string;
  sellerEmail: string;
  status: "Available" | "Sold" | "Unpublished";
  createdAt?: Date;
}

export interface TTransaction {
  _id?: ObjectId;
  transactionId: string;
  type: "purchase" | "publishing fee";
  productId?: ObjectId | null;
  productTitle?: string | null;
  buyerEmail: string;
  sellerEmail?: string | null;
  amount: number;
  createdAt: Date;
}

export interface TBookmark {
  _id?: ObjectId;
  userId: string;
  productId: string;
  productTitle: string;
  productImage: string;
  productPrice: number;
  productCategory: string;
  productSeller: string;
  createdAt: Date;
}
