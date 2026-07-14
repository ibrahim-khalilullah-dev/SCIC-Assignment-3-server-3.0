import dotenv from "dotenv";
import express, { Request, Response } from "express";

dotenv.config();

const PORT = process.env.PORT || 5000;
const app = express();

app.use(express.json());

app.get("/", (req: Request, res: Response) => {
  res.send("Server is up and running!");
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

export { app };
