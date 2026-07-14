import { ObjectId } from "mongodb";

export interface TUser {
  _id?: ObjectId;
  username: string;
  email: string;
  password?: string;
  role: "user" | "admin";
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
  createdAt?: Date;
}
