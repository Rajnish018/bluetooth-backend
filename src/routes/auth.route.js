// routes/auth.route.js
import express from "express";
import { register, login, getProfile, logout, refreshToken } from "../controller/auth.controller.js";
import { protect } from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refreshToken);

// Add 'protect' here so req.user is populated
router.get("/user", protect, getProfile); 

router.post("/logout", protect, logout);

export default router;