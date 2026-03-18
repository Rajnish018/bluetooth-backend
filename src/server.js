import express from "express";
import cors from "cors";
import dotenv from "dotenv";

import connectDB from "./db/db.js";
import authRoutes from "./routes/auth.route.js";

dotenv.config();

const app = express();


console.log("server is listening!!!!")

// Middleware

app.use(cors());
app.use(express.json());



// Routes

// Change this in server.js
app.get("/api", (req, res) => {
  res.json({ message: "API is running", status: "ok" });
});

app.use("/api/auth", authRoutes);

// Connect to DB

connectDB();

// Start Server

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(` Server running on port ${PORT}`);
});